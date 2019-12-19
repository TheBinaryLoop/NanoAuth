using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace NanoAuth.Models.Account
{
    public class RegisterInputModel
    {
        [Required]
        [StringLength(20, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 4)]
        [Display(Name = "Username")]
        public string Username { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }

        [Required]
        [DisplayName("First name")]
        public string FirstName{ get; set; }

        [Required]
        [DisplayName("Last name")]
        public string LastName{ get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email{ get; set; }

        public string ReturnUrl { get; set; }
    }
}