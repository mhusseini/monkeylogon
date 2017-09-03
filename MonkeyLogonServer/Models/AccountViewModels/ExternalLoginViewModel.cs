using System.ComponentModel.DataAnnotations;

namespace MonkeyLogon.Models.AccountViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
