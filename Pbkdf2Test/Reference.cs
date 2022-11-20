using System.Security.Cryptography;
using System.Text;
using Pbkdf2;

namespace Pbkdf2Test;

[TestFixture]
public class Reference
{

    [Test]

    [TestCase("SHA1", "pw", "salt", 1, 20)]
    [TestCase("SHA1", "pw", "salt", 1, 19)]
    [TestCase("SHA1", "pw", "salt", 2, 20)]
    [TestCase("SHA1", "pw", "salt", 3, 20)]
    [TestCase("SHA1", "pw", "salt", 10, 20)]
    [TestCase("SHA1", "pw", "salt", 1, 200)]
    [TestCase("SHA1", "pw", "salt", 10, 200)]
    [TestCase("SHA1", "pw", "salt", 10, 199)]

    [TestCase("SHA512", "pwd", "salt!", 10, 201)]
    public void CompareHMACImplementations(string algorithmName, string password, string salt, int interations, int desiredKeyLength)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var reference = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, saltBytes, interations, new HashAlgorithmName(algorithmName), desiredKeyLength);
        var testedImplementation = Compute.Pbkdf2("HMAC" + algorithmName, passwordBytes, saltBytes, interations, desiredKeyLength);
        Assert.AreEqual(reference, testedImplementation);
    }
}
