using System;
using System.Threading.Tasks;
using FitnessApp.IdentityServer.Data;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace FitnessApp.IdentityServer
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            Console.Title = "IdentityServer4";
            var host = CreateWebHostBuilder(args).Build();
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            if (environment == Environments.Development)
            {
                await DataInitializer.EnsureDefaultUsersAreCreatedAsync(host.Services);
            }
            await DataInitializer.EnsureAdminIsCreatedAsync(host.Services);
            await DataInitializer.EnsureRolesAsync(host.Services);
            await host.RunAsync();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            return WebHost.CreateDefaultBuilder(args)
                    .UseStartup<Startup>()
                    .UseSerilog((context, configuration) =>
                    {
                        configuration
                            .MinimumLevel.Debug()
                            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                            .MinimumLevel.Override("System", LogEventLevel.Warning)
                            .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                            .Enrich.FromLogContext()
                            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Literate);
                    });
        }
    }
}
