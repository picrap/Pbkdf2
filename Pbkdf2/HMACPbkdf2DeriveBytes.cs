using System;
using System.Security.Cryptography;

namespace Pbkdf2;

public class HmacPbkdf2DeriveBytes : Pbkdf2DeriveBytes
{
    private readonly HMAC _hmac;

    protected override int BlockLength => _hmac.HashSize / 8;

    public HmacPbkdf2DeriveBytes(HMAC hmac, byte[] salt, int iterations) : base(salt, iterations)
    {
        _hmac = hmac;
    }

    public HmacPbkdf2DeriveBytes(string hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(Pbkdf2.CreateHMAC(hashAlgorithmName, password), salt, iterations)
    {
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _hmac.Dispose();
    }

#if NET6_0_OR_GREATER
    public HmacPbkdf2DeriveBytes(HashAlgorithmName hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(hashAlgorithmName.Name, password, salt, iterations)
    {
    }
#endif

    protected override byte[] PseudoRandomFunction(byte[] data, object context)
    {
        lock (_hmac)
            return _hmac.ComputeHash(data);
    }
}
