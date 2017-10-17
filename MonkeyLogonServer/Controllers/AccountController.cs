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
using MonkeyLogon.Helpers;
using MonkeyLogon.Models;
using MonkeyLogon.Models.AccountViewModels;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

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

        [HttpGet("~/account/authorize")]
        [AllowAnonymous]
        public IActionResult Authorize(OpenIdConnectRequest request, string remoteError = null)
        {
            this.ViewData["State"] = this.dataProtectionProvider.ProtectQueryString(this.Request.Query);

            return this.View(nameof(this.Login));
        }

        [HttpGet("~/account/authorize"), QueryStringRequired("a")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallbackEmbedded(OpenIdConnectRequest request, string remoteError = null)
        {
            return await this.ExternalLoginCallback(request.RedirectUri, remoteError, JwtBearerDefaults.AuthenticationScheme);
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

        private string CreateReconstructableRedirectUrl(string state)
        {
            return this.Url.Action(nameof(this.ExternalLoginCallbackEmbedded), "Account", new Dictionary<string, string>
            {
                {"a", "excb"},
                {DataProtectionProviderExtensions.StateQuerystringKey, state}
            });
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