using System.ComponentModel.DataAnnotations;

namespace NanoAuth.Models
{
    public class ReCaptchaTokenInputModel
    {
        [Required]
        public string Token { get; set; }
    }
}