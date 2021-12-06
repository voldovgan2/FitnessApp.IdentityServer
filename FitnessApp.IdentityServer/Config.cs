using IdentityServer4.Models;
using System.Collections.Generic;

namespace FitnessApp.IdentityServer
{
    public class Config
    {
        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource("api_userProfile", "UserProfile API")
                {
                    Scopes = {new Scope("api.userProfile") }
                },
                new ApiResource("api_settings", "Settings API")
                {
                    Scopes = {new Scope("api.settings") }
                },
                new ApiResource("api_contacts", "Contacts API")
                {
                    Scopes = {new Scope("api.contacts") }
                },
                new ApiResource("api_notifications", "Notifications API")
                {
                    Scopes = {new Scope("api.notifications") }
                },
                new ApiResource("api_food", "Food API")
                {
                    Scopes = {new Scope("api.food") }
                },
                new ApiResource("api_exercises", "Exercises API")
                {
                    Scopes = {new Scope("api.exercises") }
                }
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
            // client credentials client
            return new[]
            {
                new Client {
                    RequireConsent = false,
                    ClientId = "angular",
                    ClientName = "angular",
                    AllowedGrantTypes = GrantTypes.Implicit,
                    AllowedScopes =
                    {
                        "openid",
                        "profile",
                        "email",
                        "api.userProfile",
                        "api.settings",
                        "api.contacts",
                        "api.notifications",
                        "api.food",
                        "api.exercises"
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
                new Client {
                    RequireConsent = false,
                    ClientId = "domain_client",
                    ClientName = "domain_client",
                    ClientSecrets =
                    {
                         new Secret("domain_client_secret".Sha256())
                    },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes =
                    {
                        "openid",
                        "profile",
                        "email",
                        "api.userProfile",
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
