using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace NanoAuth.Models.Account
{
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        [DisplayName("Remember me")]
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }
}