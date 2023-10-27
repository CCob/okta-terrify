namespace OktaVerify.Entity {
    internal class DeviceEnrollment {

        public string Id {get; set; }
        public string AuthenticatorId { get; set; }
        public string UserId { get; set; }
        public string OrganizationId { get; set; }
        public string ExternalUrl { get; set; }
        public string DeviceId { get; set; }
        public string SerializedEnrollments { get; set; }
        public string DeviceLink { get; set; }
        public string AuthenticatorLink { get; set; }
        public string EnrollmentLink { get; set; }
    }
}
