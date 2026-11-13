namespace CredGuard.Services;

/// <summary>
/// Provides hashing services for password management using the BCrypt algorithm.
/// </summary>
public static class HashingService
{
    /// <summary>
    /// Hashes a password using the BCrypt algorithm with the specified work factor.
    /// The work factor determines the computational complexity of the hashing process.
    /// </summary>
    /// <param name="password">The password to hash.</param>
    /// <param name="factor">The work factor for the hashing process.</param>
    /// <returns>The hashed password.</returns>
    public static string HashPassword(string password, int factor)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, factor);
    }

    /// <summary>
    /// Verifies a password against a hashed password.
    /// </summary>
    /// <param name="password">The password to verify.</param>
    /// <param name="hashedPassword">The hashed password to compare against.</param>
    /// <returns>true if the password matches the hashed password; otherwise, false.</returns>
    public static bool VerifyPassword(string password, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
    }
}
