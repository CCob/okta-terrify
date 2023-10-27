using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using PBKDF2;

namespace OktaCommon.DPAPI {

    public enum MasterKeyType {
        User,
        System
    }

    public enum AlgId {
        Des = 0x6601,
        Des3 = 0x6603,        
        Aes128 = 0x660e,
        Aes192 = 0x660f,
        Aes256 = 0x6610,
        Aes = 0x6611,
        Rc4 = 0x6801,
        Md5 = 0x8003,
        SHA1 = 0x8004,
        Hmac = 0x8009,
        SHA256 = 0x800c,
        SHA384 = 0x800d,        
        SHA512 = 0x800e,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public class MasterKeyHeader {
        public uint Version;
        public uint Unknown1;
        public uint Unknown2;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 36)]
        public string Guid;
        public uint Unknown3;
        public uint Policy;
        public uint Flags;
        public long MasterKeyLen;
        public long BackupKeyLen;
        public long CredHistoryLen;
        public long DomainKeyLen;
    }

    public class MasterKey {
        public uint Version;
        public byte[] Salt;
        public uint Rounds;
        public AlgId AlgHash;
        public AlgId AlgCrypt;
        public byte[] EncryptedKey;
        private byte[] _key;

        struct HashInfo {
            public string Name;
            public Type HashType;            
            public int KeySize;            
        }

        struct KeyInfo {
            public Type KeyType;
            public int KeySize;
            public int IVSize;
        }

        private static readonly Dictionary<AlgId, HashInfo> hmacTypes = new Dictionary<AlgId, HashInfo>() {
            {AlgId.SHA1, new HashInfo(){Name = "HMACSHA1", HashType = typeof(HMACSHA1), KeySize = 32} },
            {AlgId.SHA512, new HashInfo(){Name = "HMACSHA512", HashType = typeof(HMACSHA512), KeySize = 48}},
        };

        private static readonly Dictionary<AlgId, KeyInfo> keyTypes = new Dictionary<AlgId, KeyInfo>() {
            {AlgId.Aes256, new KeyInfo(){KeyType = typeof(AesManaged), KeySize = 32, IVSize = 16} },
            {AlgId.Des3, new KeyInfo(){KeyType = typeof(TripleDESCryptoServiceProvider), KeySize = 25, IVSize = 8}},
        };

        public byte[] Key {
            get {
                if (_key == null) {
                    throw new InvalidOperationException("MasterKey has not been decrypted, call Decrypt first");
                }
                return _key;
            }
        }

        public MasterKey(BinaryReader br, int recordSize) {            
            Version = br.ReadUInt32();
            Salt = br.ReadBytes(16);
            Rounds = br.ReadUInt32();
            AlgHash = (AlgId)br.ReadUInt32();
            AlgCrypt = (AlgId)br.ReadUInt32();
            EncryptedKey = br.ReadBytes(recordSize - 32);             
        }

        public void Decrypt(byte[] sha1mk) {

            if (!keyTypes.TryGetValue(AlgCrypt, out var keyInfo)) {
                throw new NotImplementedException($"Crypto algorithm type {AlgCrypt} not currently supported");
            }

            var sessionKey = DeriveSessionKey(sha1mk, out HashInfo hashInfo);

            SymmetricAlgorithm sa = (SymmetricAlgorithm)Activator.CreateInstance(keyInfo.KeyType);
            sa.Key = sessionKey.Take(keyInfo.KeySize).ToArray();
            sa.IV = sessionKey.Skip(keyInfo.KeySize).Take(keyInfo.IVSize).ToArray();
            sa.Mode = CipherMode.CBC;
            sa.Padding = PaddingMode.Zeros;

            var decrypted = sa.CreateDecryptor().TransformFinalBlock(EncryptedKey, 0, EncryptedKey.Length);
            var masterKeyFull = decrypted.Skip(decrypted.Length - 64).Take(64).ToArray();

            using (var sha1 = new SHA1Managed()) {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);
                if(!IsValidHMAC(decrypted, masterKeyFull, sha1mk, hashInfo)) {
                    throw new CryptographicException("Failed to validate HMAC, is the DPAPI SHA1 key correct?");
                }
                _key = masterKeyFull;
            }
        }   
  
        private bool IsValidHMAC(byte[] plaintextBytes, byte[] masterKeyFull, byte[] shaBytes, HashInfo hashInfo)  {
            
            var hmacObj1 = HMAC.Create(hashInfo.Name);
            hmacObj1.Key = shaBytes;
                               
            var hmacObj2 = HMAC.Create(hashInfo.Name);
            hmacObj2.Key = hmacObj1.ComputeHash(plaintextBytes, 0, 16);
            
            var hmac = new byte[hmacObj1.HashSize / 8];
            Array.Copy(plaintextBytes, 16, hmac, 0, hmac.Length);
            return hmac.SequenceEqual(hmacObj2.ComputeHash(masterKeyFull));         
        }

        private byte[] DeriveSessionKey(byte[] shaBytes, out HashInfo hashInfo) {

            if (!hmacTypes.TryGetValue(AlgHash, out hashInfo)) {
                throw new NotImplementedException($"Hash algorithm type {AlgHash} not currently supported");
            }            
           
            using (var hmac = HMAC.Create(hashInfo.Name)) {
                return new Pbkdf2(hmac, shaBytes, Salt, (int)Rounds).GetBytes(hashInfo.KeySize);
            }
        }
    }

    public class MasterKeyFile {

        public MasterKeyHeader Header;
        public MasterKey MasterKey;
        public MasterKey BackupKey;
        public MasterKey DomainKey;
        public MasterKeyType KeyType;

        public MasterKeyFile(MasterKeyType keyType, byte[] masterKeyData) {

            KeyType = keyType;

            var br = new BinaryReader(new MemoryStream(masterKeyData));

            try {

                Header = br.ReadStruct<MasterKeyHeader>();

                if (Header.Version == 0 || Header.Version > 2 || Header.MasterKeyLen == 0) {
                    throw new FormatException();
                }

                int headerSize = Marshal.SizeOf(Header);

                if (Header.MasterKeyLen > 0) {
                    br.BaseStream.Seek(headerSize, SeekOrigin.Begin);
                    MasterKey = new MasterKey(br, (int)Header.MasterKeyLen);
                }

                if (Header.BackupKeyLen > 0) {
                    br.BaseStream.Seek(headerSize + Header.MasterKeyLen, SeekOrigin.Begin);
                    BackupKey = new MasterKey(br, (int)Header.BackupKeyLen);
                }

                //TODO: read CredHistory;

                if (Header.DomainKeyLen > 0) {
                    br.BaseStream.Seek(headerSize + Header.MasterKeyLen + Header.BackupKeyLen + Header.CredHistoryLen, SeekOrigin.Begin);
                    DomainKey = new MasterKey(br, (int)Header.DomainKeyLen);
                }

            } catch (EndOfStreamException) {
                throw new FormatException();
            }
        }

        public static MasterKeyFile FindMasterKey(MasterKeyType keyType, Guid guid, string keysFolder) {
         
            if (!Directory.Exists(keysFolder))
                return null;

            var keys = Directory.EnumerateFiles(keysFolder);

            foreach (var key in keys)
            {
                try
                {
                    MasterKeyFile mkf = new MasterKeyFile(keyType, File.ReadAllBytes(key));

                    if (guid.Equals(Guid.Parse(mkf.Header.Guid)))
                    {
                        return mkf;
                    }
                }
                catch (FormatException) { }
            }
            
            return null;
        }

        public static MasterKeyFile FindMasterKey(Guid guid) {
            
            var result = FindMasterKey(MasterKeyType.User, guid, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), $@"Microsoft\Protect\{WindowsIdentity.GetCurrent().User}"));

            if (result == null)
                result = FindMasterKey(MasterKeyType.System, guid, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), $@"Microsoft\Protect\S-1-5-18\User"));

            return result;
        }
    }
}
