using System.Security.Cryptography;

namespace Pbkdf2;

public static class Compute // TODO: come up with a better name
{
    public static byte[] Pbkdf2(HMAC prf, byte[] password, byte[] salt, int count, int desiredKeyLength)
    {
        throw new NotImplementedException();
    }
}