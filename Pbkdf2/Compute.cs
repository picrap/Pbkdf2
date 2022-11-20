using System.Security.Cryptography;

namespace Pbkdf2;

public static class Compute // TODO: come up with a better name
{
    public static byte[] Pbkdf2(string algorithmName, byte[] password, byte[] salt, int count, int desiredKeyLength)
    {
        using var pbkdf2 = new HMACPbkdf2DeriveBytes(algorithmName, password, salt, count);
        return pbkdf2.GetBytes(desiredKeyLength);
    }
}