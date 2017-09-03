using System.Threading.Tasks;

namespace MonkeyLogon.Services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
