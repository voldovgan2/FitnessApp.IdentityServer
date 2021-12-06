using AspNetCore.Identity.Mongo.Model;

namespace FitnessApp.IdentityServer.Data
{
    public class ApplicationUser : MongoUser<string>
    {
        public ApplicationUser(string email)
            : base(email)
        {
            Id = $"ApplicationUser_{email}";
            Email = email;
        }
    }
}