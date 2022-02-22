using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.ViewModels
{
    public class RegisterVm
    {
        #region Properties

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


        #endregion
    }
}
