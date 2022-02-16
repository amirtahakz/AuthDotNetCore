using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.ViewModels
{
    public class LoginVm
    {
        #region Properties

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

        #endregion
    }
}
