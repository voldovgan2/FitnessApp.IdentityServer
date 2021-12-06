using FitnessApp.IdentityServer.Configuration;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace FitnessApp.IdentityServer.Services.EmailService
{
    public class EmailService : IEmailService
    {
        private EmailSettings _emailSettings;

        public EmailService(IOptions<EmailSettings> emailConfig)
        {
            _emailSettings = emailConfig.Value;
        }

        public Task SendEmailAsync(string email, string subject, string message)
        {
            var mailMessage = new MailMessage(_emailSettings.SenderEmail, email, subject, message);
            mailMessage.IsBodyHtml = true;
            NetworkCredential netCred = new NetworkCredential(_emailSettings.SenderEmail, _emailSettings.SenderPassword);
            SmtpClient smtpobj = new SmtpClient(_emailSettings.Smtp, _emailSettings.Port);
            smtpobj.EnableSsl = _emailSettings.UseSsl;
            smtpobj.Credentials = netCred;
            smtpobj.Send(mailMessage);
            return Task.CompletedTask;
        }
    }
}