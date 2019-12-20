using System.Threading.Tasks;

namespace NanoAuth.Services
{
    public interface IEmailSender
    {
        Task SendVerifyEmailEmailAsync(string email, string subject, string name, string verifyLink);
        Task SendEmailAsync(string email, string subject, string htmlMessage);
    }
}