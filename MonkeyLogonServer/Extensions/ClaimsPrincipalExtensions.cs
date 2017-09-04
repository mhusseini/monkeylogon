using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Core;

namespace MonkeyLogon.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        private static readonly Dictionary<string, string> IdentityClaimScopes = new Dictionary<string, string>
        {
            {OpenIdConnectConstants.Claims.Name, OpenIdConnectConstants.Scopes.Profile},
            {OpenIdConnectConstants.Claims.Email, OpenIdConnectConstants.Scopes.Email},
            {OpenIdConnectConstants.Claims.Role, OpenIddictConstants.Claims.Roles}
        };

        public static AuthenticationTicket CreateAuthenticationTicket(this ClaimsPrincipal principal, string securityStampClaimType)
        {
            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(principal,
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId,
                OpenIdConnectConstants.Scopes.Email,
                OpenIdConnectConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Roles);//.Intersect(request.GetScopes()));

            ticket.SetResources(ApplicationInfo.AppName);

            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            foreach (var claim in from c in ticket.Principal.Claims
                // Never include the security stamp in the access and identity tokens, as it's a secret value.
                where c.Type != securityStampClaimType
                select c)
            {
                var destinations = new List<string>
                {
                    OpenIdConnectConstants.Destinations.AccessToken
                };

                if (IdentityClaimScopes.TryGetValue(claim.Type, out string scope) && ticket.HasScope(scope))
                {
                    destinations.Add(OpenIdConnectConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }
    }
}