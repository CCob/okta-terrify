using System.Collections.Generic;
using Newtonsoft.Json;

namespace OktaTerrify.ApiTypes {

    public class Jwk {
        public string alg { get; set; }
        public string kid { get; set; }
        public string kty { get; set; }
        [JsonProperty("okta:kpr")]
        public string kpr { get; set; }
        public string use { get; set; }
        public string e { get; set; }
        public string n { get; set; }
    }

    public class Keys {
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Jwk userVerification;
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Jwk userVerificationBioOrPin;
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public Jwk proofOfPossession;        
    }

    public class Method {
        public Keys keys;
        public string type;
    }

    public class DeviceAttestation{
        public string clientInstanceKeyAttestation;        
    }

    public class Device {
        public string displayName;
        public string osVersion;
        public string platform;
        public string clientInstanceBundleId;
        public string clientInstanceDeviceSdkVersion;
        public string clientInstanceId;
        public string clientInstanceVersion;
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public DeviceAttestation deviceAttestation;
        public string id;
    }

    public class Authenticator {
        public Device device;
        public List<Method> methods = new List<Method>();
    }
}
