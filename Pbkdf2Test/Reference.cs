using System.Security.Cryptography;
using System.Text;
using Pbkdf2;

namespace Pbkdf2Test;

using Pbkdf2;
using NUnit.Framework;

[TestFixture]
public class Reference
{

    [Test]

    [TestCase("SHA1", "pw", "salt", 1, 20)]
    [TestCase("SHA1", "pw", "salt", 1, 19)]
    [TestCase("SHA1", "pw", "salt", 1, 21)]
    [TestCase("SHA1", "pw", "salt", 2, 20)]
    [TestCase("SHA1", "pw", "salt", 3, 20)]
    [TestCase("SHA1", "pw", "salt", 10, 20)]
    [TestCase("SHA1", "pw", "salt", 1, 200)]
    [TestCase("SHA1", "pw", "salt", 10, 200)]
    [TestCase("SHA1", "pw", "salt", 10, 199)]

    [TestCase("SHA512", "pwd", "salt!", 10, 201)]
    public void CompareHMACImplementations(string algorithmName, string password, string salt, int iterations, int desiredKeyLength)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var reference = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, saltBytes, iterations, new HashAlgorithmName(algorithmName), desiredKeyLength);
        var testedImplementation = Pbkdf2.HashData("HMAC" + algorithmName, passwordBytes, saltBytes, iterations, desiredKeyLength);
        Assert.That(reference, Is.EqualTo(testedImplementation));
    }
}