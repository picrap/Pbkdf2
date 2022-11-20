using System.Security.Cryptography;

namespace Pbkdf2;

public class HMACPbkdf2DeriveBytes : Pbkdf2DeriveBytes
{
    private readonly HMAC _hmac;

    protected override int BlockLength => _hmac.HashSize / 8;

    public HMACPbkdf2DeriveBytes(HMAC hmac, byte[] salt, int count, int desiredKeyLength) : base(salt, count, desiredKeyLength)
    {
        _hmac = hmac;
    }

    public HMACPbkdf2DeriveBytes(string hashAlgorithmName, byte[] password, byte[] salt, int count, int desiredKeyLength)
        : this(CreateHMAC(hashAlgorithmName, password), salt, count, desiredKeyLength)
    {
    }

#if NET6_0_OR_GREATER
    public HMACPbkdf2DeriveBytes(HashAlgorithmName hashAlgorithmName, byte[] password, byte[] salt, int count, int desiredKeyLength)
        : this(hashAlgorithmName.Name, password, salt, count, desiredKeyLength)
    {
    }
#endif
    private static HMAC CreateHMAC(string hashAlgorithmName, byte[] password)
    {
        var hmac = HMAC.Create(hashAlgorithmName);
        if (hmac is null)
            throw new ArgumentException($"Unknown hash algorithm {hashAlgorithmName}");
        hmac.Key = password;
        return hmac;
    }

    protected override byte[] PseudoRandomFunction(byte[] data)
    {
        return _hmac.ComputeHash(data);
    }
}
