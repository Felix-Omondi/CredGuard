using System.IdentityModel.Tokens.Jwt;
using System.Text;
using CredGuard.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace CredGuard.Extensions;

/// <summary>
/// Extension methods for IServiceCollection to add CredGuard services and configure JWT authentication and OpenAPI documentation.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds CredGuard services, configures JWT authentication, and sets up OpenAPI documentation with Bearer security scheme.
    /// </summary>
    /// <param name="services">The IServiceCollection to add services to.</param>
    /// <param name="configuration">The IConfiguration instance.</param>
    /// <returns>The updated IServiceCollection.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the JWT key is not configured.</exception>
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
