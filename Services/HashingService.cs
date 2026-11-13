namespace CredGuard.Services;

public static class HashingService
{
    public static string HashPassword(string password, int factor)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, factor);
    }

    public static bool VerifyPassword(string password, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(password, hashedPassword);
    }
}
