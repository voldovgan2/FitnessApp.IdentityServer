using System.Collections.Generic;
using Duende.IdentityServer.Models;

namespace FitnessApp.IdentityServer
{
    public static class Config
    {
        public static IEnumerable<ApiScope> ApiScopes => new List<ApiScope>
        {
            new ApiScope(name: "api.profile", displayName: "UserProfile API"),
            new ApiScope(name: "api.settings", displayName: "Settings API"),
            new ApiScope(name: "api.contacts", displayName: "Contacts API"),
            new ApiScope(name: "api.notifications", displayName: "Notifications API"),
            new ApiScope(name: "api.food", displayName: "Food API"),
            new ApiScope(name: "api.exercises", displayName: "Exercises API")
        };

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("api_profile", "UserProfile API") { Scopes = { "api.profile" } },
                new ApiResource("api_settings", "Settings API") { Scopes = { "api.settings" } },
                new ApiResource("api_contacts", "Contacts API") { Scopes = { "api.contacts" } },
                new ApiResource("api_notifications", "Notifications API") { Scopes = { "api.notifications" } },
                new ApiResource("api_food", "Food API") { Scopes = { "api.food" } },
                new ApiResource("api_exercises", "Exercises API") { Scopes = { "api.exercises" } }
            };
        }

        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Email(),
                new IdentityResources.Profile(),
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                new Client
                {
                    RequireConsent = false,
                    ClientId = "angular",
                    ClientName = "angular",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes =
                    {
                        "openid",
                        "profile",
                        "email",
                        "api"
                    },
                    RedirectUris =
                    {
                        "http://localhost:4200/home",
                        "http://localhost:4200/auth-callback",
                        "http://localhost:4200/",
                        "http://localhost:4200/silent-refresh"
                    },
                    PostLogoutRedirectUris =
                    {
                        "http://localhost:4200/"
                    },
                    AllowedCorsOrigins =
                    {
                        "http://localhost:4200"
                    },
                    AllowAccessTokensViaBrowser = true,
                    AccessTokenLifetime = 360
                },
                new Client
                {
                    RequireConsent = false,
                    ClientId = "domain_client",
                    ClientName = "domain_client",
                    ClientSecrets =
                    {
                        new Secret("domain_client_secret".Sha256()),
                        new Secret("domain_client_secret"),
                    },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes =
                    {
                        "openid",
                        "profile",
                        "email",
                        "api.profile",
                        "api.settings",
                        "api.contacts",
                        "api.food",
                        "api.exercises"
                    },
                    AccessTokenLifetime = 60
                }
            };
        }
    }
}
