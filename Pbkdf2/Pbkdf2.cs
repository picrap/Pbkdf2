
namespace Pbkdf2;

public static class Pbkdf2 
{
    public static byte[] Compute(string algorithmName, byte[] password, byte[] salt, int count, int desiredKeyLength)
    {
        using var pbkdf2 = new HMACPbkdf2DeriveBytes(algorithmName, password, salt, count);
        return pbkdf2.GetBytes(desiredKeyLength);
    }
}