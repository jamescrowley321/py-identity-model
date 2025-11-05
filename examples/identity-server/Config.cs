using System.Text.Json;
using Duende.IdentityServer.Models;

namespace IdentityServerHost
{
    public class IdentityServerConfig
    {
        public ApiScopeConfig ApiScope { get; set; } = new();
        public List<ClientConfig> Clients { get; set; } = new();
    }

    public class ApiScopeConfig
    {
        public string Name { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
    }

    public class ClientConfig
    {
        public string ClientId { get; set; } = string.Empty;
        public List<string> AllowedGrantTypes { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
        public bool RequireClientSecret { get; set; }
        public bool AllowOfflineAccess { get; set; }
        public int AccessTokenLifetime { get; set; }
        public List<string> RedirectUris { get; set; } = new();
        public List<string> PostLogoutRedirectUris { get; set; } = new();
    }

    public static class Config
    {
        private static IdentityServerConfig? _config;

        private static IdentityServerConfig LoadConfig()
        {
            if (_config != null)
                return _config;

            var configPath = Path.Combine(AppContext.BaseDirectory, "identityserver-config.json");
            if (!File.Exists(configPath))
            {
                throw new FileNotFoundException($"Configuration file not found: {configPath}");
            }

            var json = File.ReadAllText(configPath);
            _config = JsonSerializer.Deserialize<IdentityServerConfig>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? throw new InvalidOperationException("Failed to deserialize configuration");

            return _config;
        }

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

        public static IEnumerable<ApiScope> ApiScopes
        {
            get
            {
                var config = LoadConfig();
                return new ApiScope[]
                {
                    new ApiScope(config.ApiScope.Name, config.ApiScope.DisplayName),
                };
            }
        }

        public static IEnumerable<ApiResource> ApiResources
        {
            get
            {
                var config = LoadConfig();
                return new ApiResource[]
                {
                    new ApiResource(config.ApiScope.Name, config.ApiScope.DisplayName)
                    {
                        Scopes = { config.ApiScope.Name }
                    },
                };
            }
        }

        public static IEnumerable<Client> Clients
        {
            get
            {
                var config = LoadConfig();
                var clients = new List<Client>();

                foreach (var clientConfig in config.Clients)
                {
                    var client = new Client
                    {
                        ClientId = clientConfig.ClientId,
                        AllowedScopes = clientConfig.AllowedScopes,
                        RequireClientSecret = clientConfig.RequireClientSecret,
                        AllowOfflineAccess = clientConfig.AllowOfflineAccess,
                        AccessTokenLifetime = clientConfig.AccessTokenLifetime,
                        RedirectUris = clientConfig.RedirectUris,
                        PostLogoutRedirectUris = clientConfig.PostLogoutRedirectUris
                    };

                    // Set grant types
                    if (clientConfig.AllowedGrantTypes.Contains("client_credentials"))
                    {
                        client.AllowedGrantTypes = GrantTypes.ClientCredentials;
                    }
                    else if (clientConfig.AllowedGrantTypes.Contains("authorization_code"))
                    {
                        client.AllowedGrantTypes = GrantTypes.Code;
                    }

                    // Set client secrets based on client ID
                    if (clientConfig.ClientId == "py-identity-model-client")
                    {
                        client.ClientSecrets = new List<Secret> { new Secret(GetClientSecret().Sha256()) };
                    }
                    else if (clientConfig.ClientId == "py-identity-model-test")
                    {
                        client.ClientSecrets = new List<Secret> { new Secret(GetTestClientSecret().Sha256()) };
                    }

                    clients.Add(client);
                }

                return clients;
            }
        }
    }
}