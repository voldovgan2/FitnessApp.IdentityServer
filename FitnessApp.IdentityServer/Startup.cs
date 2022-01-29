using System;
using AspNetCore.Identity.Mongo;
using FitnessApp.Common.Serializer.JsonSerializer;
using FitnessApp.IdentityServer.Configuration;
using FitnessApp.IdentityServer.Data;
using FitnessApp.IdentityServer.Services.EmailService;
using FitnessApp.ServiceBus.AzzureServiceBus.Configuration;
using FitnessApp.ServiceBus.AzzureServiceBus.Producer;
using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace FitnessApp.IdentityServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc(options =>
            {
                options.EnableEndpointRouting = false;
            });

            services
                .AddIdentityMongoDbProvider<ApplicationUser, ApplicationRole, string>(identityOptions =>
                {
                    identityOptions.Password.RequiredLength = 6;
                    identityOptions.Password.RequireLowercase = true;
                    identityOptions.Password.RequireUppercase = true;
                    identityOptions.Password.RequireNonAlphanumeric = false;
                    identityOptions.Password.RequireDigit = true;

                    identityOptions.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                    identityOptions.Lockout.MaxFailedAccessAttempts = 5;
                    identityOptions.Lockout.AllowedForNewUsers = true;

                    identityOptions.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                    identityOptions.User.RequireUniqueEmail = true;
                }, mongoIdentityOptions =>
                {
                    mongoIdentityOptions.ConnectionString = Configuration.GetConnectionString("Mongo");
                })
                .AddDefaultTokenProviders();

            // This is required to ensure server can identify user after login
            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.ExpireTimeSpan = TimeSpan.FromDays(30);
                options.SlidingExpiration = true;
            });

            // ---  configure identity server with MONGO Repository for stores, keys, clients and scopes ---
            services.AddIdentityServer(options =>
            {
                options.Authentication.CookieLifetime = TimeSpan.FromDays(30);
                options.Authentication.CookieSlidingExpiration = true;
            })
                .AddDeveloperSigningCredential()
                .AddInMemoryIdentityResources(Config.GetIdentityResources())
                .AddInMemoryApiResources(Config.GetApiResources())
                .AddInMemoryClients(Config.GetClients())
                .AddAspNetIdentity<ApplicationUser>();

            services.AddAuthentication()
                .AddOpenIdConnect("oidc", "OpenID Connect", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                    options.Authority = "http://localhost:5000";
                    options.ClientId = "angular";

                    options.RequireHttpsMetadata = false;

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                })
                .AddFacebook(facebookOptions =>
                {
                    facebookOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    facebookOptions.AppId = Configuration.GetValue<string>("ExternalLoginProviders:0:AppID");
                    facebookOptions.AppSecret = Configuration.GetValue<string>("ExternalLoginProviders:0:AppSecret");
                })
                .AddMicrosoftAccount(microsoftOptions =>
                {
                    microsoftOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    microsoftOptions.ClientId = Configuration.GetValue<string>("ExternalLoginProviders:1:AppID");
                    microsoftOptions.ClientSecret = Configuration.GetValue<string>("ExternalLoginProviders:1:AppSecret");
                })
                .AddGoogle(googleOptions =>
                {
                    googleOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    googleOptions.ClientId = Configuration.GetValue<string>("ExternalLoginProviders:2:AppID");
                    googleOptions.ClientSecret = Configuration.GetValue<string>("ExternalLoginProviders:2:AppSecret");
                });

            services.Configure<EmailSettings>(Configuration.GetSection("EmailSettings"));

            services.AddTransient<IJsonSerializer, JsonSerializer>();

            services.Configure<AzzureServiceBusSettings>(Configuration.GetSection("AzzureServiceBusSettings"));

            services.AddTransient<IMessageProducer, MessageProducer>();

            services.AddTransient<IEmailService, EmailService>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Verbose()
                .Enrich.FromLogContext()
                .WriteTo.File(@"authserver_log.txt");

            loggerFactory.WithFilter(new FilterLoggerSettings
                {
                    { "IdentityServer4", LogLevel.Debug },
                    { "Microsoft", LogLevel.Warning },
                    { "System", LogLevel.Warning },
                }).AddSerilog(serilog.CreateLogger());

            app.UseIdentityServer();
            app.UseAuthentication();
            app.UseStaticFiles();
            app.UseMvcWithDefaultRoute();
        }
    }
}