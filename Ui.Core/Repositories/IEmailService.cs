using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.ViewModels;

namespace Ui.Core.Repositories
{
    public interface IEmailService
    {
        #region IMethods

        Task SendEmailAsync(EmailModel email);

        #endregion
    }
}
