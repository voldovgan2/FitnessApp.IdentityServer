using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace FitnessApp.IdentityServer.Data
{
    public class DataInitializer
    {
        public static async Task EnsureDefaultUsersAreCreatedAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var services = scope.ServiceProvider;
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                for (int k = 0; k < 200; k++)
                {
                    var email = $"user{k}@hotmail.com";
                    var user = await userManager.FindByEmailAsync(email);
                    if (user == null)
                    {
                        var newUser = new ApplicationUser(email) { EmailConfirmed = true };
                        await userManager.CreateAsync(newUser, "_4Ccess");
                    }
                }
            }
        }

        public static async Task EnsureAdminIsCreatedAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var services = scope.ServiceProvider;
                var configuration = services.GetRequiredService<IConfiguration>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                var adminEmail = configuration.GetValue<string>("AdminCredentials:Email");
                var admin = await userManager.FindByEmailAsync(adminEmail);
                if (admin == null)
                {
                    var user = new ApplicationUser(adminEmail) { EmailConfirmed = true };
                    await userManager.CreateAsync(user, configuration.GetValue<string>("AdminCredentials:Password"));
                }
            }
        }

        public static async Task EnsureRolesAsync(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var services = scope.ServiceProvider;
                var configuration = services.GetRequiredService<IConfiguration>();
                var roleManager = services.GetRequiredService<RoleManager<ApplicationRole>>();
                var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
                if (!await roleManager.RoleExistsAsync("Admin"))
                {
                    await roleManager.CreateAsync(new ApplicationRole("Admin"));
                }
                var admin = await userManager.FindByEmailAsync(configuration.GetValue<string>("AdminCredentials:Email"));
                await userManager.AddToRoleAsync(admin, "Admin");
                if (!await roleManager.RoleExistsAsync("Coach"))
                {
                    await roleManager.CreateAsync(new ApplicationRole("Coach"));
                }
                if (!await roleManager.RoleExistsAsync("User"))
                {
                    await roleManager.CreateAsync(new ApplicationRole("User"));
                }
            }
        }
    }
}