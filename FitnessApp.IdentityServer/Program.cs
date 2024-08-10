using System;
using System.Collections.Generic;
using AspNetCore.Identity.Mongo;
using Duende.IdentityServer;
using Duende.IdentityServer.Test;
using FitnessApp.Common.Configuration;
using FitnessApp.IdentityServer;
using FitnessApp.IdentityServer.Configuration;
using FitnessApp.IdentityServer.Data;
using FitnessApp.IdentityServer.Services.EmailService;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var isLocal = true;
if (isLocal)
    ConfigureInMemoryIdentityServer(builder);
else
    ConfigureIdentityServer(builder);

builder.Services.AddMvc(options =>
{
    options.EnableEndpointRouting = false;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
});

builder.Services
    .AddAuthentication()
    .AddOpenIdConnect("oidc", "OpenID Connect", options =>
    {
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        options.SignOutScheme = IdentityServerConstants.SignoutScheme;

        options.Authority = builder.Configuration.GetValue<string>("OpenIdConnect:Authority");
        options.ClientId = builder.Configuration.GetValue<string>("OpenIdConnect:ClientId");
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
        facebookOptions.AppId = builder.Configuration.GetValue<string>("ExternalLoginProviders:0:AppID");
        facebookOptions.AppSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:0:AppSecret");
    })
    .AddMicrosoftAccount(microsoftOptions =>
    {
        microsoftOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        microsoftOptions.ClientId = builder.Configuration.GetValue<string>("ExternalLoginProviders:1:AppID");
        microsoftOptions.ClientSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:1:AppSecret");
    })
    .AddGoogle(googleOptions =>
    {
        googleOptions.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
        googleOptions.ClientId = builder.Configuration.GetValue<string>("ExternalLoginProviders:2:AppID");
        googleOptions.ClientSecret = builder.Configuration.GetValue<string>("ExternalLoginProviders:2:AppSecret");
    });

builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
builder.Services.ConfigureNats(builder.Configuration);

builder.Services.AddTransient<IEmailService, EmailService>();
builder.Services.AddHealthChecks();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
}

app.UseIdentityServer();
app.UseAuthentication();
app.UseStaticFiles();
app.UseMvcWithDefaultRoute();
app.MapHealthChecks("/health");

app.Run();

void ConfigureInMemoryIdentityServer(WebApplicationBuilder builder)
{
    builder.Services
        .AddIdentityServer(options =>
        {
            options.Authentication.CookieLifetime = TimeSpan.FromDays(30);
            options.Authentication.CookieSlidingExpiration = true;
            options.Events.RaiseErrorEvents = true;
            options.Events.RaiseFailureEvents = true;
            options.Events.RaiseInformationEvents = true;
        })
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryApiResources(Config.GetApiResources())
        .AddInMemoryClients(Config.GetClients())
        .AddInMemoryIdentityResources(Config.GetIdentityResources());
}

void ConfigureIdentityServer(WebApplicationBuilder builder)
{
    var migrationsAssembly = typeof(Program).Assembly.GetName().Name;
    const string connectionString = @"Data Source=Duende.IdentityServer.Quickstart.EntityFramework.db";
    builder.Services
                .AddIdentityMongoDbProvider<ApplicationUser, ApplicationRole, string>(
                    identityOptions =>
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
                },
                    mongoIdentityOptions =>
                {
                    mongoIdentityOptions.ConnectionString = builder.Configuration.GetConnectionString("Mongo");
                })
                .AddDefaultTokenProviders();

    builder.Services
        .AddIdentityServer(options =>
        {
            options.Authentication.CookieLifetime = TimeSpan.FromDays(30);
            options.Authentication.CookieSlidingExpiration = true;
        })
        .AddConfigurationStore(options =>
        {
            options.ConfigureDbContext = b => b.UseNpgsql(
                connectionString,
                sql => sql.MigrationsAssembly(migrationsAssembly));
        })
        .AddOperationalStore(options =>
        {
            options.ConfigureDbContext = b => b.UseNpgsql(
                connectionString,
                sql => sql.MigrationsAssembly(migrationsAssembly));
        })
        .AddTestUsers(new List<TestUser>
        {
            new TestUser
            {
                Username = "savaTest",
                Password = "password",
                IsActive = true
            }
        });
}

public partial class Program { }
