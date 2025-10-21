using Duende.IdentityServer.Models;

namespace IdentityServerHost
{
    public static class Config
    {
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

        public static IEnumerable<Client> Clients =>
            new Client[]
            {
                new Client
                {
                    ClientId = "py-identity-model-client",
                    ClientSecrets = { new Secret("py-identity-model-secret".Sha256()) },
                    
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
                    ClientSecrets = { new Secret("test-secret".Sha256()) },
                    
                    AllowedGrantTypes = GrantTypes.Code,
                    AllowedScopes = { "openid", "profile", "py-identity-model" },
                    
                    RedirectUris = { "https://localhost:5002/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
                    
                    AccessTokenLifetime = 3600,
                }
            };
    }
}