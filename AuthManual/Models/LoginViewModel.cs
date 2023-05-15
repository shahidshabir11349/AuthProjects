using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace AuthManual.Models
{
    public class LoginViewModel
    {
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DisplayName("Remember me?")] 
        public bool RememberMe { get; set; }
    }
}
