using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Duende.IdentityServer;
using Duende.IdentityServer.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace FitnessApp.IdentityServer.Extensions
{
    public static class Extensions
    {
        public static async Task<bool> IsPkceClient(this IClientStore store, string client_id)
        {
            if (!string.IsNullOrWhiteSpace(client_id))
            {
                var client = await store.FindEnabledClientByIdAsync(client_id);
                return client.RequirePkce;
            }

            return false;
        }

        public static async Task SignIn(this HttpContext context, string subject, string name, AuthenticationProperties properties, params Claim[] claims)
        {
            IdentityServerUser user = new IdentityServerUser(subject)
            {
                DisplayName = name,
                AdditionalClaims = claims,
                AuthenticationTime = TimeProvider.System.GetUtcNow().UtcDateTime
            };
            await context.SignInAsync(user, properties);
        }

        public static async Task<bool> GetSchemeSupportsSignOut(this HttpContext context, string scheme)
        {
            var provider = context.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
            var handler = await provider.GetHandlerAsync(context, scheme);
            return handler is IAuthenticationSignOutHandler;
        }
    }
}
