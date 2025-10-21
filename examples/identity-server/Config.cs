using Duende.IdentityServer.Models;

namespace IdentityServerHost
{
    public static class Config
    {
        // Read secrets from environment variables with fallback defaults for development
        private static string GetClientSecret() =>
            Environment.GetEnvironmentVariable("CLIENT_SECRET") ?? "py-identity-model-secret";

        private static string GetTestClientSecret() =>
            Environment.GetEnvironmentVariable("TEST_CLIENT_SECRET") ?? "test-secret";

        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("py-identity-model", "Python Identity Model API"),
            };

        public static IEnumerable<ApiResource> ApiResources =>
            new ApiResource[]
            {
                new ApiResource("py-identity-model", "Python Identity Model API")
                {
                    Scopes = { "py-identity-model" }
                },
            };

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                {
                    ClientId = "py-identity-model-client",
                    ClientSecrets = { new Secret(GetClientSecret().Sha256()) },
                    
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = { "py-identity-model" },
                    
                    // For testing purposes
                    RequireClientSecret = true,
                    AllowOfflineAccess = true,
                    AccessTokenLifetime = 3600,
                },
                
                new Client
                {
                    ClientId = "py-identity-model-test",
                    ClientSecrets = { new Secret(GetTestClientSecret().Sha256()) },
                    
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "profile", "py-identity-model" },
                    
                    RedirectUris = { "https://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
                    
                    AccessTokenLifetime = 3600,
                }
            };
    }
}