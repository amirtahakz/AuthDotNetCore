using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Repositories;
using Ui.Core.ViewModels;

namespace Ui.Client.Controllers
{
    public class AccountController : Controller
    {
        #region Connections

        private IExampleService _exampleService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IViewRenderService _viewRenderService;

        public AccountController(IExampleService userService, UserManager<IdentityUser> userManager, IEmailService emailService, SignInManager<IdentityUser> signInManager, IViewRenderService viewRenderService)
        {
            _exampleService = userService;
            _userManager = userManager;
            _emailService = emailService;
            _signInManager = signInManager;
            _viewRenderService = viewRenderService;
        }

        #endregion

        #region Controllers

        public IActionResult Index()
        {
            ViewBag.IsSent = false;
            return View();
        }
        public IActionResult Register()
        {
            ViewBag.IsSent = false;
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterVm model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.IsSent = false;
                return View(model);
            }

            var email = await _userManager.FindByEmailAsync(model.Email);
            if (email != null)
            {
                ModelState.AddModelError(string.Empty, "Email already exists!");
                return View(model);
            }

            var result = await _userManager.CreateAsync(new IdentityUser()
            {
                Email = model.Email,
                UserName = model.Email,
                PhoneNumber = model.Phone
            }, model.Password);

            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, err.Description);
                    ViewBag.IsSent = false;
                    return View(model);
                }
            }
            // Send Email Confirmation Code
            var user = await _userManager.FindByEmailAsync(model.Email);
            var emailCode = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            string body = await _viewRenderService.RenderToStringAsync("Account/_RegisterEmail", emailCode);
            await _emailService.SendEmailAsync(new EmailVm(user.Email, "Confirm account email", body));

            return RedirectToAction("ConfirmEmailCode", new { email = user.Email});
        }
        public IActionResult ConfirmEmailCode(string email)
        {
            if (string.IsNullOrEmpty(email)) return BadRequest();
            ViewBag.IsSent = true;
            ConfirmEmailCodeVm confirmEmailCodeVm = new ConfirmEmailCodeVm()
            {
                Email = email,
            };

            return View(confirmEmailCodeVm);
        }
        [HttpPost]
        public async Task<IActionResult> ConfirmEmailCode(ConfirmEmailCodeVm model)
        {
            if (!ModelState.IsValid) return View();

            var user = _userManager.Users.SingleOrDefault(u => u.Email == model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found!");
                return View();
            }

            bool result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.Code);
            if (!result)
            {
                ModelState.AddModelError(string.Empty, "Code is not valid");
                return View(model);
            }

            user.EmailConfirmed = true;
            await _userManager.UpdateAsync(user);

            return RedirectToAction("Login");
        }



        public async Task<IActionResult> Login(string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            LoginVm model = new LoginVm()
            {
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList(),
            };
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Login(LoginVm model, string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ViewBag.ReturnUrl = returnUrl;

            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found!");
                return View(model);
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                ModelState.AddModelError(string.Empty, "Please confirm your email");
                return View(model);
            }

            var result =
                await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

            if (result.Succeeded)
            {
                if (Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);
                else
                    return RedirectToAction("Index", "Home");
            }
            else if (result.RequiresTwoFactor)
            {
                return RedirectToAction("LoginWith2fa");
            }
            else if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Account locked out");
                return View(model);
            }

            ModelState.AddModelError(string.Empty, "Attempt to enter invalid");
            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }



        public IActionResult ForgotPassword()
        {
            ViewBag.IsSent = false;
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVm model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.IsSent = false;
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Attempt to send email failed");
                ViewBag.IsSent = false;
                return View();
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                ModelState.AddModelError(string.Empty, "Please confirm your email");
                return View();
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            string? callBackUrl = Url.ActionLink("ResetPassword", "Account", new { email = user.Email, token = token }, Request.Scheme);
            string body = await _viewRenderService.RenderToStringAsync("Account/_ResetPasswordEmail", callBackUrl);
            await _emailService.SendEmailAsync(new EmailVm(user.Email, "Password recovery", body));
            ViewBag.IsSent = true;
            return View();
        }


        [AllowAnonymous]
        public IActionResult ResetPassword(string email, string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token)) return BadRequest();

            ResetPasswordVm model = new ResetPasswordVm()
            {
                Email = email,
                Token = token
            };

            return View(model);
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordVm model)
        {
            if (!ModelState.IsValid) return View();

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Attempt to recover password failed");
                return View(model);
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                ModelState.AddModelError(string.Empty, "Please confirm your email");
                return View();
            }

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token));
            var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, err.Description);
                }
            }

            return RedirectToAction("Login");
        }


        [HttpPost]
        public IActionResult ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Account",
                                new { ReturnUrl = returnUrl });
            var properties = _signInManager
                .ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return new ChallengeResult(provider, properties);
        }

        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");
            ViewBag.ReturnUrl = returnUrl;

            LoginVm loginViewModel = new LoginVm
            {
                ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList()
            };

            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider: {remoteError}");

                return View("Login", loginViewModel);
            }

            // Get the login information about the user from the external login provider
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                ModelState.AddModelError(string.Empty, "Error loading external login information.");

                return View("Login", loginViewModel);
            }

            // If the user already has a login (i.e if there is a record in AspNetUserLogins
            // table) then sign-in the user with this external login provider
            var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider,
                info.ProviderKey, isPersistent: false, bypassTwoFactor: true);

            if (signInResult.Succeeded)
            {
                return LocalRedirect(returnUrl);
            }
            // If there is no record in AspNetUserLogins table, the user may not have
            // a local account
            else
            {
                // Get the email claim value
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);

                if (email != null)
                {
                    // Create a new user without password if we do not have a user already
                    var user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        user = new IdentityUser
                        {
                            UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
                            Email = info.Principal.FindFirstValue(ClaimTypes.Email)
                        };

                        await _userManager.CreateAsync(user);
                    }

                    // Add a login (i.e insert a row for the user in AspNetUserLogins table)
                    await _userManager.AddLoginAsync(user, info);
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnUrl);
                }

                // If we cannot find the user email we cannot continue
                ViewBag.ErrorTitle = $"Email claim not received from: {info.LoginProvider}";
                ViewBag.ErrorMessage = "Please contact support on Pragim@PragimTech.com";

                return View("Error");
            }
        }


        #endregion
    }
}
