namespace OktaTerrify.Entity {
    internal class OktaVerifyInformation {

        public string Id { get; set; }
        public byte[] InstanceIdentifier { get; set; }
        public string SandboxName { get; set; }
        public int SandboxState { get; set; }
        public byte[] ApplicationKeyProtectionSeed { get; set; }
    }
}
