using System.Diagnostics;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Duende.IdentityServer;
using Duende.IdentityServer.Extensions;
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

        internal static ISystemClock GetClock(this HttpContext context)
        {
            return context.RequestServices.GetRequiredService<ISystemClock>();
        }

        public static async Task SignIn(this HttpContext context, string subject, string name, AuthenticationProperties properties, params Claim[] claims)
        {
            ISystemClock clock = context.GetClock();
            IdentityServerUser user = new IdentityServerUser(subject)
            {
                DisplayName = name,
                AdditionalClaims = claims,
                AuthenticationTime = clock.UtcNow.UtcDateTime
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
