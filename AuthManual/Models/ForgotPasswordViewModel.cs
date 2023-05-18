using System.ComponentModel.DataAnnotations;

namespace AuthManual.Models
{
    public class ForgotPasswordViewModel
    {
        [EmailAddress]
        public string Email { get; set; }
    }
}
