namespace MsalAuthInMaui
{
    public class Settings
    {
        // Azure AD B2C Microsoft Authentication
        public string ClientId { get; set; } = null;
        public string TenantId { get; set; } = null;
        public string Authority { get; set; } = null;
        public NestedSettings[] Scopes { get; set; } = null;

        // Azure AD B2C Twitter Authentication
        public string ClientIdForTwitter { get; set; } = null;
        public string TenantForTwitter { get; set; } = null;
        public string TenantIdForTwitter { get; set; } = null;
        public string InstanceUrlForTwitter { get; set; } = null;
        public string PolicySignUpSignInForTwitter { get; set; } = null;
        public string AuthorityForTwitter { get; set; } = null;
        public NestedSettings[] ScopesForTwitter { get; set; } = null;
    }
}