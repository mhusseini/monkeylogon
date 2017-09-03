using System.ComponentModel.DataAnnotations;

namespace MonkeyLogon.Models.AccountViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
