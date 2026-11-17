using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;
using System.Text;
using System.Security.Claims;
using System.Security.Cryptography;

namespace CredGuard.Services;

/// <summary>
/// Provides services for generating JSON Web Tokens (JWT) for authentication and authorization.
/// </summary>
public class TokenService
{
    private readonly IConfiguration _configuration;

    /// <summary>
    /// Initializes a new instance of the <see cref="TokenService"/> class with the specified configuration.
    /// </summary>
    /// <param name="configuration">The IConfiguration instance.</param>
    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    /// <summary>
    /// Generates a JSON Web Token (JWT) for the specified user information.
    /// </summary>
    /// <param name="name">The name of the user.</param>
    /// <param name="email">The email of the user.</param>
    /// <param name="role">The role of the user.</param>
    /// <returns>The generated JWT.</returns>
    /// <exception cref="InvalidOperationException">Thrown when required JWT settings are missing from configuration.</exception>
    public string GenerateToken(string name, string email, string role)
    {
        var jwtKey = _configuration["JwtSettings:Key"] ?? throw new InvalidOperationException("JwtSettings:Key is missing from configuration.");
        byte[] keyBytes = Encoding.UTF8.GetBytes(jwtKey);
        var key = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Email,email),
                new (JwtRegisteredClaimNames.Name,name),
                new ("role", role)
        };

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:ExpiryMinutes"] ?? "15")),
            Issuer = _configuration["JwtSettings:Issuer"],
            Audience = _configuration["JwtSettings:Audience"],
            SigningCredentials = credentials,
            IssuedAt = DateTime.UtcNow
        };

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(descriptor);

        return token;
    }

    /// <summary>
    /// Generates a cryptographically secure random refresh token.
    /// </summary>
    /// <returns>A Base64-encoded 64-byte random string.</returns>
    public string GenerateRefreshToken()
    {
        byte[] randomBytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(randomBytes);
    }

    /// <summary>
    /// Calculates the UTC expiration timestamp for a new refresh token based on configuration.
    /// </summary>
    /// <returns>The UTC <see cref="DateTime"/> when the refresh token expires.</returns>
    public DateTime GetRefreshTokenExpiry()
    {
        var expiryDays = Convert.ToDouble(_configuration["JwtSettings:RefreshTokenExpiryDays"] ?? "7");
        return DateTime.UtcNow.AddDays(expiryDays);
    }
}
