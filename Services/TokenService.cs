using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;
using System.Text;
using System.Security.Claims;

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
    public (string, DateTime) GenerateToken(string name, string email, string role)
    {
        var jwtKey = _configuration["JwtSettings:TokenSecret"] ?? throw new InvalidOperationException("JwtSettings:TokenSecret is missing from configuration.");
        byte[] keyBytes = Encoding.UTF8.GetBytes(jwtKey);
        var key = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new (JwtRegisteredClaimNames.Email,email),
                new (JwtRegisteredClaimNames.Name,name),
                new ("role", role)
        };

        var expirationDate = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["JwtSettings:ExpiryMinutes"] ?? "15"));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expirationDate,
            Issuer = _configuration["JwtSettings:Issuer"],
            Audience = _configuration["JwtSettings:Audience"],
            SigningCredentials = credentials,
            IssuedAt = DateTime.UtcNow
        };

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(descriptor);

        return (token, expirationDate);
    }

    /// <summary>
    /// Generates a signed JWT refresh token valid for 7 days.
    /// </summary>
    /// <returns>A signed JWT string.</returns>
    public string GenerateRefreshToken()
    {
        var refreshTokenKey = _configuration["JwtSettings:RefreshTokenSecret"] ?? throw new InvalidOperationException("JwtSettings:RefreshTokenSecret is missing from configuration.");
        byte[] keyBytes = Encoding.UTF8.GetBytes(refreshTokenKey);
        var key = new SymmetricSecurityKey(keyBytes);
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expirationDate = DateTime.UtcNow.AddDays(7);

        var descriptor = new SecurityTokenDescriptor
        {
            // Subject = new ClaimsIdentity(claims),
            Expires = expirationDate,
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
    /// Calculates the UTC expiration timestamp for a new refresh token based on configuration.
    /// </summary>
    /// <returns>The UTC <see cref="DateTime"/> when the refresh token expires.</returns>
    public DateTime GetRefreshTokenExpiry()
    {
        var expiryDays = Convert.ToDouble(_configuration["JwtSettings:RefreshTokenExpiryDays"] ?? "7");
        return DateTime.UtcNow.AddDays(expiryDays);
    }

    /// <summary>
    /// Validates the signature, issuer, audience, and expiration of a JWT refresh token.
    /// </summary>
    /// <param name="refreshToken">The JWT refresh token string provided by the client.</param>
    /// <returns>True if the token is valid and unexpired; otherwise, false.</returns>
    public async Task<bool> ValidateRefreshToken(string refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return false;
        }

        var refreshTokenKey = _configuration["JwtSettings:RefreshTokenSecret"] ?? throw new InvalidOperationException("JwtSettings:RefreshTokenSecret is missing from configuration.");
        byte[] keyBytes = Encoding.UTF8.GetBytes(refreshTokenKey);
        var key = new SymmetricSecurityKey(keyBytes);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidIssuer = _configuration["JwtSettings:Issuer"],
            ValidAudience = _configuration["JwtSettings:Audience"],
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        var handler = new JsonWebTokenHandler();
        var tokenValidationResult = await handler.ValidateTokenAsync(refreshTokenKey, validationParameters);

        return tokenValidationResult.IsValid;
    }
}
