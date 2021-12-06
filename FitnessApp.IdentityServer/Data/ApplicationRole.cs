using AspNetCore.Identity.Mongo.Model;

namespace FitnessApp.IdentityServer.Data
{
    public class ApplicationRole : MongoRole<string>
    {
        public ApplicationRole(string name)
            : base(name)
        {
            Id = $"ApplicationRole_{name}";
        }
    }
}