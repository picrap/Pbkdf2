
using System;
using System.Security.Cryptography;
using System.Text;

namespace Pbkdf2;

public static class Pbkdf2
{
    public static byte[] HashData(string algorithmName, string password, byte[] salt, int iterations, int desiredKeyLength)
    {
        return HashData(algorithmName, Encoding.UTF8.GetBytes(password), salt, iterations, desiredKeyLength);
    }

    public static byte[] HashData(string algorithmName, byte[] password, byte[] salt, int iterations, int desiredKeyLength)
    {
        using var pbkdf2 = new HmacPbkdf2DeriveBytes(algorithmName, password, salt, iterations);
        return pbkdf2.GetBytes(desiredKeyLength);
    }

    public static byte[] HashData(HMAC hmac, byte[] salt, int iterations, int desiredKeyLength)
    {
        using var pbkdf2 = new HmacPbkdf2DeriveBytes(hmac, salt, iterations);
        return pbkdf2.GetBytes(desiredKeyLength);
    }

#if NET6_0_OR_GREATER
    public static byte[] ParallelHashData(Func<HMAC> createHmac, byte[] salt, int iterations, int desiredKeyLength)
    {
        using var pbkdf2 = new ParallelHmacPbkdf2DeriveBytes(createHmac, salt, iterations);
        return pbkdf2.GetBytes(desiredKeyLength);
    }
#endif

    internal static HMAC CreateHMAC(string hashAlgorithmName, byte[] password)
    {
        return hashAlgorithmName?.ToUpper() switch
        {
            "HMACMD5" or "MD5" => new HMACMD5(password),
            "HMACSHA1" or "SHA1" => new HMACSHA1(password),
            "HMACSHA256" or "SHA256" => new HMACSHA256(password),
            "HMACSHA384" or "SHA384" => new HMACSHA384(password),
            "HMACSHA512" or "SHA512" => new HMACSHA512(password),
            _ => throw new ArgumentException($"Unknown hash algorithm {hashAlgorithmName}")
        };
    }
}
