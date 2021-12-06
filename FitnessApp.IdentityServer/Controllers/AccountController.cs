// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using FitnessApp.IdentityServer.Attributes;
using FitnessApp.IdentityServer.Data;
using FitnessApp.IdentityServer.Extensions;
using FitnessApp.IdentityServer.Models.Account;
using FitnessApp.IdentityServer.Models.Home;
using FitnessApp.IdentityServer.Services.EmailService;
using FitnessApp.NatsServiceBus;
using FitnessApp.Serializer.JsonSerializer;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace FitnessApp.IdentityServer.Controllers
{
    /// <summary>
    /// This sample controller implements a typical login/logout/provision workflow for local and external accounts.
    /// The login service encapsulates the interactions with the user data store. This data store is in-memory only and cannot be used for production!
    /// The interaction service provides a way for the UI to communicate with identityserver for validation and context retrieval
    /// </summary>
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly IJsonSerializer _serializer;
        private readonly IServiceBus _serviceBus;

        public AccountController
        (
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailService emailService,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IEventService events,
            IServiceBus serviceBus,
            IJsonSerializer serializer
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _serviceBus = serviceBus;
            _serializer = serializer;
        }

        #region Register

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpGet]
        //public async Task<IActionResult> Register()
        public async Task<IActionResult> Register(ReturnViewModel args)
        {            
            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes.Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase)))
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var vm = new RegisterViewModel
            {
                ReturnUrl = args.ReturnUrl,
                ExternalProviders = providers.ToArray()
            };
            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string button)
        {
            if (button == "register")
            {
                if (ModelState.IsValid)
                {                    
                    var existingUseruser = await _userManager.FindByEmailAsync(model.Email);
                    if (existingUseruser != null)
                    {
                        await _userManager.DeleteAsync(existingUseruser);
                    }
                    var user = new ApplicationUser(model.Email);
                    var result = await _userManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, Request.Scheme);
                        await _emailService.SendEmailAsync(model.Email, "Confirm your email", $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                        return View("RegistrationCompleted", new RegistrationCompletedViewModel { Result = "Registration successful, please confirm your email." });
                    }
                    else
                    {
                        return View("Error", new ErrorViewModel(result.Errors.Select(e => e.Description)));
                    }
                }
                else
                {
                    var vm = new RegisterViewModel
                    {
                        ReturnUrl = model.ReturnUrl,
                    };
                    return View(vm);
                }
            }
            else if (button == "login")
            {
                return RedirectToAction("Login");
            }
            else
            {
                return View("Error", new ErrorViewModel("’ÛÈ ÈÓ„Ó ÁÌ‡∫ ‰Â ˇ ∫!"));
            }            
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            ConfirmEmailResultModel model = new ConfirmEmailResultModel();
            if (userId != null && code != null)
            {
                var user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    var result = await _userManager.ConfirmEmailAsync(user, code);
                    if (result.Succeeded)
                    {
                        result = await _userManager.AddToRoleAsync(user, "User");
                        if (result.Succeeded)
                        {
                            _serviceBus.PublishEvent(IntegrationEvents.Topic.NEW_USER_REGISTERED, _serializer.SerializeToBytes(new IntegrationEvents.NewUserRegisteredEvent
                            {
                                UserId = userId,
                                Email = user.Email                                
                            }));
                            model.Result = true;
                            model.Data = "Thank you for confirming your email.";
                        }
                        else
                        {
                            model.Result = false;
                            model.Data = "Failed to assign user to default role.";
                        }
                    }
                    else
                    {
                        model.Result = false;
                        model.Data = $"Error confirming email for user with ID: '{userId}'.";
                    }
                }
                else
                {
                    model.Result = false;
                    model.Data = $"Unable to load user with ID: '{userId}'.";
                }
            }
            else
            {
                model.Result = false;
                model.Data ="Invalid user id or confirmation code.";
            }
            return View("ConfirmEmailResult", model);
        }

        #endregion

        #region Login

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputViewModel model, string button)
        {
            if (button == "register")
            {                
                return RedirectToAction("Register",new ReturnViewModel { ReturnUrl = model.ReturnUrl });
            }
            else if (button == "forgot")
            {
                return RedirectToAction("ForgotPassword");
            }
            else
            {
                // check if we are in the context of an authorization request
                var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

                // the user clicked the "cancel" button
                if (button != "login")
                {
                    if (context != null)
                    {
                        // if the user cancels, send a result back into IdentityServer as if they 
                        // denied the consent (even if this client does not require consent).
                        // this will send back an access denied OIDC error response to the client.
                        await _interaction.GrantConsentAsync(context, ConsentResponse.Denied);

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        if (await _clientStore.IsPkceClientAsync(context.ClientId))
                        {
                            // if the client is PKCE then we assume it's native, so this change in how to
                            // return the response is for better UX for the end user.
                            return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                        }

                        return Redirect(model.ReturnUrl);
                    }
                    else
                    {
                        // since we don't have a valid context, then we just go back to the home page
                        return Redirect("~/");
                    }
                }

                if (ModelState.IsValid)
                {
                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberLogin, lockoutOnFailure: true);
                    if (result.Succeeded)
                    {
                        var user = await _userManager.FindByEmailAsync(model.Email);
                        await _events.RaiseAsync(new UserLoginSuccessEvent(user.Email, user.Id, user.Email, clientId: context?.ClientId));

                        // only set explicit expiration here if user chooses "remember me". 
                        // otherwise we rely upon expiration configured in cookie middleware.
                        AuthenticationProperties props = null;
                        if (AccountOptions.AllowRememberLogin && model.RememberLogin)
                        {
                            props = new AuthenticationProperties
                            {
                                IsPersistent = true,
                                ExpiresUtc = DateTimeOffset.UtcNow.Add(AccountOptions.RememberMeLoginDuration)
                            };
                        };

                        // issue authentication cookie with subject ID and username
                        await HttpContext.SignInAsync(user.Id, user.Email, props);

                        if (context != null)
                        {
                            if (await _clientStore.IsPkceClientAsync(context.ClientId))
                            {
                                // if the client is PKCE then we assume it's native, so this change in how to
                                // return the response is for better UX for the end user.
                                return View("Redirect", new RedirectViewModel { RedirectUrl = model.ReturnUrl });
                            }

                            // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                            return Redirect(model.ReturnUrl);
                        }

                        // request for a local page
                        if (Url.IsLocalUrl(model.ReturnUrl))
                        {
                            return Redirect(model.ReturnUrl);
                        }
                        else if (string.IsNullOrEmpty(model.ReturnUrl))
                        {
                            return Redirect("~/");
                        }
                        else
                        {
                            // user might have clicked on a malicious link - should be logged
                            throw new Exception("invalid return URL");
                        }
                    }

                    await _events.RaiseAsync(new UserLoginFailureEvent(model.Email, "invalid credentials", clientId: context?.ClientId));
                    ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
                }

                // something went wrong, show form with error
                var vm = await BuildLoginViewModelAsync(model);
                return View(vm);
            }
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    //ReturnUrl = returnUrl,
                    Email = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } };
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null ||
                            (x.Name.Equals(AccountOptions.WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase))
                )
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Email = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputViewModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Email = model.Email;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        #endregion

        #region Forgot passowrd

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ForgotPassword()
        {
            return View("ForgotPassword");
        }
                
        [HttpPost]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    return View("Error", new ErrorViewModel("User Was Not Found"));
                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action("ResetPassword", "Account", new { code = code, email = model.Email }, Request.Scheme);
                await _emailService.SendEmailAsync(model.Email, "Reset Password", $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");
                return View("ForgotPasswordCompleted", new ForgotPasswordResultViewModel { Message = "Reset password confirmation email was sent, please check your email box and confirm it." });
            }
            else
            {               
                return View(new ForgotPasswordViewModel());
            }
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> ResetPassword(string code, string email)
        {
            if (code != null)
            {
                ResetPasswordViewModel model = new ResetPasswordViewModel() { Code = code, Email= email };
                return View("ConfirmResetPassword", model);
            }
            else
            {
                return View("ConfirmResetPassword", null);
            }
        }

        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> ConfirmResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                ConfirmResetPasswordResultModel resultModel = null;
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
                    if (result.Succeeded)
                    {
                        resultModel = new ConfirmResetPasswordResultModel(true, "Successfully reset password!");
                    }
                    else
                    {
                        resultModel = new ConfirmResetPasswordResultModel(false, result.Errors.Select(e => e.Description));
                    }
                }
                else
                {
                    resultModel = new ConfirmResetPasswordResultModel(false, "User was not found");
                }
                return View("ConfirmResetPasswordResult", resultModel);
            }
            else
            {
                return View(new ResetPasswordViewModel() { Code = model.Code, Email = model.Email });
            }
        }

        #endregion

        #region Logout

        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {            
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);
            await _signInManager.SignOutAsync();
            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await HttpContext.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return View("LoggedOut", vm);
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }

        #endregion

        #region Error

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #endregion
    }
}
