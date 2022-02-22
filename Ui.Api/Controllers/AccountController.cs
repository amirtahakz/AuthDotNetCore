using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Repositories;
using Ui.Core.ViewModels;
using Ui.Data.Entities;



namespace Ui.Api.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        #region Connections

        private readonly IExampleService _exampleService;
        private IConfiguration _configuration;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly ITokenGeneratorService _tokenGeneratorService;

        public AccountController(IConfiguration config, IExampleService exampleService, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IEmailService emailService, ITokenGeneratorService tokenGeneratorService)
        {
            _exampleService = exampleService;
            _configuration = config;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _tokenGeneratorService = tokenGeneratorService;
        }

        #endregion

        #region Controllers

        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginApiVm model)
        {

            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "User is not valid" });


            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new ResponseVm { Status = "Error", Response = "Please confirm your email" });
                }

                var userRoles = await _userManager.GetRolesAsync(user);

                string accessToken = _tokenGeneratorService.GenerateToken(user, userRoles);
                string refreshToken = _tokenGeneratorService.GenerateRefreshToken();
                var res = _tokenGeneratorService.GetByUserId(user.Id);
                if (res.Result != null)
                {
                    await _tokenGeneratorService.DeleteRefreshToken(res.Result.Id);
                }



                UserRefreshToken item = new UserRefreshToken()
                {
                    RefreshToken = refreshToken,
                    UserId = user.Id,
                };
                await _tokenGeneratorService.CreateRefreshToken(item);

                return Ok(new ResponseVm { Status = "Success", Response = new { accessToken, refreshToken } });
            }
            return Unauthorized();
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenVm model)
        {

            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "model is not valid" });

            bool isValidRefreshToken = _tokenGeneratorService.ValidateRefreshToken(model.RefreshToken);
            if (!isValidRefreshToken)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "Invalid refresh token." });
            }

            UserRefreshToken res = await _tokenGeneratorService.GetByRefreshToken(model.RefreshToken);
            if (res == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "Invalid refresh token." });
            }

            var user = await _userManager.FindByIdAsync(res.UserId);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "User not found." });
            }


            await _tokenGeneratorService.DeleteRefreshToken(res.Id);

            var userRoles = await _userManager.GetRolesAsync(user);
            string accessToken = _tokenGeneratorService.GenerateToken(user, userRoles);
            string refreshToken = _tokenGeneratorService.GenerateRefreshToken();

            UserRefreshToken item = new UserRefreshToken()
            {
                RefreshToken = refreshToken,
                UserId = user.Id,
            };
            await _tokenGeneratorService.CreateRefreshToken(item);

            return Ok(new ResponseVm { Status = "Success", Response = new { accessToken, refreshToken } });

        }

        [HttpPost]
        [AllowAnonymous]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterVm model)
        {
            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "User is not valid" });

            var email = await _userManager.FindByEmailAsync(model.Email);
            if (email != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseVm { Status = "Error", Response = "User already exists!" });


            var result = await _userManager.CreateAsync(new IdentityUser()
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.Phone
            }, model.Password);


            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseVm { Status = "Error", Response = "User creation failed! Please check user details and try again." });


            // Send Email Confirmation Code
            var user = await _userManager.FindByEmailAsync(model.Email);
            var emailCode = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            string body = System.IO.File.ReadAllText
                (@"E:\Dot Net Core Projects\My\Identity\DotNetCore\Ui.Api\Tools\RegisterEmailConfirmation.html") + emailCode;
            await _emailService.SendEmailAsync(new EmailVm(user.Email, "Confirm account email", body));


            return Ok(new ResponseVm { Status = "Success", Response = "User created successfully! please confirm your email" });
        }


        [HttpPost]
        [Route("RegisterAdmin")]
        [Authorize(Roles = UserRolesVm.Admin)]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterVm model)
        {

            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "User is not valid" });

            var email = await _userManager.FindByEmailAsync(model.Email);
            if (email != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "User already exists!" });

            var user = new IdentityUser()
            {
                UserName = model.Email,
                Email = model.Email,
                PhoneNumber = model.Phone
            };
            var result = await _userManager.CreateAsync(user, model.Password);


            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new ResponseVm { Status = "Error", Response = "User creation failed! Please check user details and try again." });


            if (!await _roleManager.RoleExistsAsync(UserRolesVm.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRolesVm.Admin));

            if (!await _roleManager.RoleExistsAsync(UserRolesVm.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRolesVm.User));

            if (await _roleManager.RoleExistsAsync(UserRolesVm.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRolesVm.Admin);
            }

            return Ok(new ResponseVm { Status = "Success", Response = "User created successfully!" });
        }

        [HttpPost]
        [Route("ConfirmEmailCode")]
        public async Task<IActionResult> ConfirmEmailCode([FromBody] ConfirmEmailCodeVm model)
        {
            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "User is not valid" });

            var user = _userManager.Users.SingleOrDefault(u => u.Email == model.Email);
            if (user == null)
            {
                return NotFound();
            }

            bool result = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", model.Code);
            if (!result)
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseVm { Status = "Error", Response = "Email is not confirmed" });
            }

            user.EmailConfirmed = true;
            await _userManager.UpdateAsync(user);

            return Ok(new ResponseVm { Status = "Success", Response = "Your email confirmed successfully!" });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordVm model)
        {
            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "Email is not valid" });

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "User is not exists!" });

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseVm { Status = "Error", Response = "Please confirm your email" });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            string? callBackUrl = Url.ActionLink("ResetPassword", "Account",
                new { email = user.Email, token = token }, Request.Scheme);

            string html = System.IO.File.ReadAllText(@"E:\Dot Net Core Projects\My\Identity\DotNetCore\Ui.Api\Tools\ResetPasswordEmail.html");
            string body = html + callBackUrl;
            await _emailService.SendEmailAsync(new EmailVm(user.Email, "بازیابی کلمه عبور", body));

            return Ok(new ResponseVm { Status = "Success", Response = "Forgot password email sent successfully!" });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordVm model)
        {
            if (!ModelState.IsValid) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "Email is not valid" });

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "User is not exists!" });

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new ResponseVm { Status = "Error", Response = "Please confirm your email" });
            }

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token));
            var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

            if (!result.Succeeded) return StatusCode(StatusCodes.Status500InternalServerError,
                new ResponseVm { Status = "Error", Response = "Something is wrong" });

            return Ok(new ResponseVm { Status = "Success", Response = "Password Changed successfully!" });
        }

        [HttpGet]
        [Route("Privacy")]
        [Authorize]
        public async Task<IActionResult> Privacy()
        {
            return Ok();
        }


        #endregion
    }
}
