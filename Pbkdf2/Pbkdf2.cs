
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
        using var pbkdf2 = new HMACPbkdf2DeriveBytes(algorithmName, password, salt, iterations);
        return pbkdf2.GetBytes(desiredKeyLength);
    }
}