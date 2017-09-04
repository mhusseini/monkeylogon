using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MonkeyLogon.Extensions;
using MonkeyLogon.Models;
using MonkeyLogon.Models.AccountViewModels;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;

namespace MonkeyLogon.Controllers
{
    [Authorize]
    [Route("[controller]/[action]")]
    public class AccountController : Controller
    {
        private readonly IDataProtectionProvider dataProtectionProvider;
        private readonly IdentityOptions identityOptions;
        private readonly ILogger logger;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly UserManager<ApplicationUser> userManager;

        public AccountController(
            IOptions<IdentityOptions> identityOptions,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<AccountController> logger,
            IDataProtectionProvider dataProtectionProvider)
        {
            this.identityOptions = identityOptions.Value;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.logger = logger;
            this.dataProtectionProvider = dataProtectionProvider;
        }

        [TempData]
        public string ErrorMessage { get; set; }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ApiLogin(OpenIdConnectRequest request, [FromQuery(Name = "a")]string action = null, string remoteError = null)
        {
            if (action == "excb" || !string.IsNullOrWhiteSpace(remoteError))
            {
                return await this.ExternalLoginCallback(request.RedirectUri, remoteError, JwtBearerDefaults.AuthenticationScheme);
            }

            this.ViewData["State"] = this.dataProtectionProvider.ProtectQueryString(this.Request.Query);

            return this.View(nameof(this.Login));
        }

        [HttpPost]
        [Produces("application/json")]
        public async Task<IActionResult> Token(OpenIdConnectRequest request)
        {
            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            {
                return this.BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = "The specified grant type is not supported."
                });
            }

            // Retrieve the claims principal stored in the authorization code/refresh token.
            var info = await this.HttpContext.AuthenticateAsync(OpenIdConnectServerDefaults.AuthenticationScheme);

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            // Note: if you want to automatically invalidate the authorization code/refresh token
            // when the user password/roles change, use the following line instead:
            // var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
            var user = await this.userManager.GetUserAsync(info.Principal);
            if (user == null)
            {
                return this.BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "The token is no longer valid."
                });
            }

            // Ensure the user is still allowed to sign in.
            if (!await this.signInManager.CanSignInAsync(user))
            {
                return this.BadRequest(new OpenIdConnectResponse
                {
                    Error = OpenIdConnectConstants.Errors.InvalidGrant,
                    ErrorDescription = "The user is no longer allowed to sign in."
                });
            }

            // Create a new authentication ticket, but reuse the properties stored in the
            // authorization code/refresh token, including the scopes originally granted.
            var principal = await this.signInManager.CreateUserPrincipalAsync(user);
            var ticket = principal.CreateAuthenticationTicket(this.identityOptions.ClaimsIdentity.SecurityStampClaimType);

            return this.SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null, string state = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = string.IsNullOrWhiteSpace(state)
                ? this.Url.Action(nameof(this.ExternalLoginCallback), "Account", new { returnUrl })
                : this.CreateReconstructableRedirectUrl(state);
            var properties = this.signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return this.Challenge(properties, provider);
        }

        private string CreateReconstructableRedirectUrl(string state)
        {
            return this.Url.Action(nameof(this.ApiLogin), "Account", new Dictionary<string, string>
            {
                {"a", "excb"},
                {DataProtectionProviderExtensions.StateQuerystringKey, state}
            });
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null, string scheme = null)
        {
            if (remoteError != null)
            {
                this.ErrorMessage = $"Error from external provider: {remoteError}";
                return this.RedirectToAction(nameof(this.Login));
            }
            var info = await this.signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return this.RedirectToAction(nameof(this.Login));
            }

            // Sign in the user with this external login provider if the user already has a login.
            var result = await this.signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
            if (result.Succeeded)
            {
                this.logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                return scheme == JwtBearerDefaults.AuthenticationScheme
                    ? await this.SignInWithOpenIdDict(await this.userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey))
                    : this.RedirectToLocal(returnUrl);
            }
            if (result.IsLockedOut)
            {
                return this.RedirectToAction(nameof(this.Lockout));
            }

            // If the user does not have an account, then ask the user to create an account.
            this.ViewData["ReturnUrl"] = returnUrl;
            this.ViewData["LoginProvider"] = info.LoginProvider;
            if (scheme == JwtBearerDefaults.AuthenticationScheme)
            {
                this.ViewData["State"] = this.dataProtectionProvider.ProtectQueryString(this.Request.Query);
            }
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            return this.View("ExternalLogin", new ExternalLoginViewModel { Email = email });
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null, string state = null)
        {
            if (this.ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await this.signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                var result = await this.userManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await this.userManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await this.signInManager.SignInAsync(user, isPersistent: false);
                        this.logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        return !string.IsNullOrWhiteSpace(state)
                            ? this.Redirect(this.CreateReconstructableRedirectUrl(state))
                            : this.RedirectToLocal(returnUrl);
                    }
                }
                this.AddErrors(result);
            }

            this.ViewData["ReturnUrl"] = returnUrl;
            return this.View(nameof(this.ExternalLogin), model);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return this.View();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await this.HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            this.ViewData["ReturnUrl"] = returnUrl;
            return this.View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await this.signInManager.SignOutAsync();
            this.logger.LogInformation("User logged out.");
            return this.RedirectToAction(nameof(HomeController.Index), "Home");
        }

        private async Task<IActionResult> SignInWithOpenIdDict(ApplicationUser user)
        {
            var principal = await this.signInManager.CreateUserPrincipalAsync(user);
            var ticket = principal.CreateAuthenticationTicket(this.identityOptions.ClaimsIdentity.SecurityStampClaimType);

            return this.SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        #region Helpers

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                this.ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return this.Redirect(returnUrl);
            }
            else
            {
                return this.RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion Helpers
    }
}