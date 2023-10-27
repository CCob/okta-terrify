using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace OktaCommon.DPAPI {

    public interface IMasterKeyProvider {
        MasterKey GetMasterKey(Guid id);
    }

    public abstract class MasterKeyProvider : IMasterKeyProvider {

        public IEnumerable<MasterKeyFile> MasterKeyFiles { get; protected set; }

        public MasterKeyProvider(string keysFolder, byte[] sha1mk) {
            EnumerateKeys(keysFolder, sha1mk);
        }

        void EnumerateKeys(string keysFolder, byte[] sha1mk) {

            if (!Directory.Exists(keysFolder))
                return;

            var keys = Directory.EnumerateFiles(keysFolder);

            MasterKeyFiles = keys
                .Select(kf => {
                    try {
                        var mkf = new MasterKeyFile(MasterKeyType.User, File.ReadAllBytes(kf));
                        mkf.MasterKey.Decrypt(sha1mk);
                        return mkf;
                    } catch (FormatException) {
                        return null;
                    }
                }).Where(mkf => mkf != null);
        }

        public MasterKey GetMasterKey(Guid id) {

            if (MasterKeyFiles == null)
                return null;

            return MasterKeyFiles
                .Where(mkf => Guid.Parse(mkf.Header.Guid) == id)
                .SingleOrDefault()
                ?.MasterKey;
        }
    }

    public class MasterKeyProviderSystemUser : MasterKeyProvider {

        public MasterKeyProviderSystemUser() : this(LSADump.GetDPAPIKeys()[1]) {
        }

        public MasterKeyProviderSystemUser(byte[] systemDPAPIKey) 
            : base(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), $@"Microsoft\Protect\S-1-5-18\User"), systemDPAPIKey) {            
        }  
    }

    public class MasterKeyProviderLocalMachine : MasterKeyProvider {

        public MasterKeyProviderLocalMachine() : this(LSADump.GetDPAPIKeys()[0]) {
        }

        public MasterKeyProviderLocalMachine(byte[] systemDPAPIKey)
            : base(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), $@"Microsoft\Protect\S-1-5-18"), systemDPAPIKey) {
        }
    }
}
