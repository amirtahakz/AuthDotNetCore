using Microsoft.AspNetCore.Identity.UI.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using Ui.Core.Repositories;
using Ui.Core.ViewModels;

namespace Ui.Core.Services
{
    public class EmailService : IEmailService
    {
        #region Methods

        public async Task SendEmailAsync(EmailVm email)
        {
            MailMessage mail = new MailMessage()
            {
                From = new MailAddress("amirtahakazemtabarzahraei@gmail.com", "نام نمایشی"),
                To = { email.To },
                Subject = email.Subject,
                Body = email.Body,
                IsBodyHtml = true,
            };
            SmtpClient smtpServer = new SmtpClient("smtp.gmail.com", 587) // Host => forExample webmail.codeyad.com
            {
                Credentials = new System.Net.NetworkCredential("amirtahakazemtabarzahraei@gmail.com", "amirtahafilm"), // UserName == Email
                EnableSsl = true,
                UseDefaultCredentials = false,
                DeliveryMethod = SmtpDeliveryMethod.Network
            };
            smtpServer.Send(mail);
            await Task.CompletedTask;
        }

        #endregion
    }
}
