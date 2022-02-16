using System;
using System.Net;
using System.Net.Mail;


namespace Ui.Core.Utilities
{
    public static class Email
    {
        private static MailMessage _mail;
        private static SmtpClient _client;
        static Email()
        {
            _mail = new MailMessage();
            _client = new SmtpClient();
        }
        public static bool SendEmail(string to, string subject, string body)
        {
            try
            {
                _mail.From = new MailAddress("amirtahakazemtabarzahraei@gmail.com");
                _mail.To.Add(to);
                _mail.Subject = subject;
                _mail.Body = body;
                _mail.IsBodyHtml = true;

                _client.Host = "smtp.gmail.com";
                _client.Port = 587;
                _client.EnableSsl = true;
                _client.UseDefaultCredentials = false;
                _client.DeliveryMethod = SmtpDeliveryMethod.Network;
                _client.Credentials = new NetworkCredential("amirtahakazemtabarzahraei@gmail.com", "amirtahafilm");
                _client.Send(_mail);
                return true;

            }
            catch
            {
                throw new Exception("There is a problem to connect server");
            }
            finally
            {
                _mail.Dispose();
                _client.Dispose();
            }
        }
    }
}
