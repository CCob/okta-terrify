using System.Runtime.Serialization;

namespace OktaVerify.Entity {

    [DataContract(Name = "typ")]
    public enum AuthenticationMethodType {
        Unknown,
        [EnumMember(Value = "signed_nonce")]
        SignedNonce,
        [EnumMember(Value = "push")]
        Push,
        [EnumMember(Value = "totp")]
        Totp
    }

    internal class AuthenticatorVerificationMethod {


        public string Id { get; set; }
        public AuthenticationMethodType Method {  get; set; }
        public string SerializedCredentials { get; set; }
    }
}
