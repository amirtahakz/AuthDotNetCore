using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;

namespace Ui.Client.Models
{
    public class LoginVm
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }


        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }


        [Display(Name = "Remember Me?")]
        public bool RememberMe { get; set; }

        public string? ReturnUrl { get; set; }

        [Display(Name = "External Logins")]
        public IList<AuthenticationScheme>? ExternalLogins { get; set; }
    }

    public class RegisterVm
    {
        [Required(ErrorMessage = "{0} is required.")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "{0} is required.")]
        [Phone]
        public string Phone { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "{0} is required.")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Required(ErrorMessage = "{0} is required.")]
        [Compare(nameof(Password))]
        public string RePassword { get; set; }
    }

    public class RefreshTokenVm
    {
        [Required]
        public string RefreshToken { get; set; }
    }

    public class ResetPasswordVm
    {
        [Display(Name = "New Password")]
        [Required]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }


        [Display(Name = "Confirm New Password")]
        [Compare(nameof(NewPassword))]
        [DataType(DataType.Password)]
        public string ConfirmNewPassword { get; set; }


        [Required]
        public string Email { get; set; }


        [Required]
        public string Token { get; set; }
    }

    public class SendEmailCodeVm
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }

    public class ConfirmEmailCodeVm
    {
        [Required(ErrorMessage = "{0} is required.")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "{0} is required.")]
        public string Code { get; set; }
    }

    public class ExternalLoginConfirmationVm
    {
        [Required(ErrorMessage = "{0} is required.")]
        [Phone]
        public string Phone { get; set; }
    }

    public class ForgotPasswordVm
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

    }

    public class UserRolesVm
    {
        public const string Admin = "Admin";
        public const string User = "User";
    }
}
