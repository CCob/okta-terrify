namespace OktaVerify.Entity {
    internal class OrganizationInformation {
        public string Id { get; set; }
        public string Filter { get; set; }
        public string Domain { get; set; }
        public string ClientInstanceId { get; set; }
        public string SerializedOrgKeys { get; set; }
        public string SerializedDeviceKey { get; set; }
        public string DeviceId { get; set; }
    }
}
