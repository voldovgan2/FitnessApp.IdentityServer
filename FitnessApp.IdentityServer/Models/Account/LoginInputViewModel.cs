using System.ComponentModel.DataAnnotations;

namespace FitnessApp.IdentityServer.Models.Account
{
    public class LoginInputViewModel : ReturnViewModel
    {
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
    }
}