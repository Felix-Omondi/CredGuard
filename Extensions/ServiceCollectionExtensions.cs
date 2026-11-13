using System.IdentityModel.Tokens.Jwt;
using System.Text;
using CredGuard.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace CredGuard.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCredGuard(this IServiceCollection services, IConfiguration configuration)
    {
        var jwtKey = configuration["JwtSettings:Key"]
            ?? throw new InvalidOperationException("JWT key is not configured in JwtSettings:Key.");

        services.AddScoped<TokenService>();

        services.AddOpenApi(options =>
        {
            options.AddDocumentTransformer<BearerSecuritySchemeTransformer>();
        });

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            // Set to false so ASP.NET Core respects your exact claim names
            options.MapInboundClaims = false;

            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration["JwtSettings:Issuer"],
                ValidAudience = configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew = TimeSpan.Zero,
                NameClaimType = JwtRegisteredClaimNames.Name,

                // Instructs the framework to look at your custom "role" claim
                RoleClaimType = "role"
            };
        });

        services.AddAuthorization();

        return services;
    }
}
