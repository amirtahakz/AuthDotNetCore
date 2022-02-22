using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Ui.Core.ViewModels
{
    public class ExternalLoginConfirmationVm
    {
        [Required(ErrorMessage = "{0} is required.")]
        [Phone]
        public string Phone { get; set; }
    }
}
