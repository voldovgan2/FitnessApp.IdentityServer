using System.ComponentModel.DataAnnotations;

namespace FitnessApp.IdentityServer.Models.Account
{
    public class ForgotPasswordViewModel
    {
        [Required]
        public string Email { get; set; }
    }
}