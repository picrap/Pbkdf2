using System;
using System.Security.Cryptography;

namespace Pbkdf2;

#if NET6_0_OR_GREATER

public class HMACPbkdf2DeriveBytes2 : Pbkdf2DeriveBytes2
{
    private readonly HMAC _hmac;

    protected override int BlockLength => _hmac.HashSize / 8;

    public HMACPbkdf2DeriveBytes2(HMAC hmac, byte[] salt, int iterations) : base(salt, iterations)
    {
        _hmac = hmac;
    }

    public HMACPbkdf2DeriveBytes2(string hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(CreateHMAC(hashAlgorithmName, password), salt, iterations)
    {
    }

    public HMACPbkdf2DeriveBytes2(HashAlgorithmName hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(hashAlgorithmName.Name, password, salt, iterations)
    {
    }

    private static HMAC CreateHMAC(string hashAlgorithmName, byte[] password)
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

    protected override void PseudoRandomFunction(ReadOnlySpan<byte> input, Span<byte> output)
    {
        _hmac.TryComputeHash(input, output, out _);
    }
}

#endif
