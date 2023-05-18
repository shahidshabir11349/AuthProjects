using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthManual.Models
{
    public class VerifyAuthenticatorViewModel
    {
        [Required]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [DisplayName("Remember me?")]
        public bool RememberMe { get; set; }
    }
}
