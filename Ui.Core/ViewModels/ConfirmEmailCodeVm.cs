using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.ViewModels
{
    public class ConfirmEmailCodeVm
    {
        [Required(ErrorMessage = "{0} is required.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "{0} is required.")]
        public string Code { get; set; }
    }
}
