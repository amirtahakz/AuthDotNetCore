using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.ViewModels
{
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
}
