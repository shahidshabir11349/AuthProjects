using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthManual.Models
{
    public class ResetPasswordViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName("Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [DisplayName("Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [DisplayName("Confirm Password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password must match.")]
        public string ConfirmPassword { get; set;}

        public string Code { get; set; }
    }
}
