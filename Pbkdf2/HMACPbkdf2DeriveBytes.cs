using System;
using System.Security.Cryptography;

namespace Pbkdf2;

public class HMACPbkdf2DeriveBytes : Pbkdf2DeriveBytes
{
    private readonly HMAC _hmac;

    protected override int BlockLength => _hmac.HashSize / 8;

    public HMACPbkdf2DeriveBytes(HMAC hmac, byte[] salt, int iterations) : base(salt, iterations)
    {
        _hmac = hmac;
    }

    public HMACPbkdf2DeriveBytes(string hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(CreateHMAC(hashAlgorithmName, password), salt, iterations)
    {
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _hmac.Dispose();
    }

#if NET6_0_OR_GREATER
    public HMACPbkdf2DeriveBytes(HashAlgorithmName hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(hashAlgorithmName.Name, password, salt, iterations)
    {
    }
#endif

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

    protected override byte[] PseudoRandomFunction(byte[] data)
    {
        lock (_hmac)
            return _hmac.ComputeHash(data);
    }
}
