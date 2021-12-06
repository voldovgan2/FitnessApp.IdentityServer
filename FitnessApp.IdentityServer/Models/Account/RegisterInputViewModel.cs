using System.ComponentModel.DataAnnotations;

namespace FitnessApp.IdentityServer.Models.Account
{
    public class RegisterInputViewModel : ReturnViewModel
    { 
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Compare("Password", ErrorMessage = "Confirm password doesn't match, Type again !")]
        public string ConfirmPassword { get; set; }
    }
}
