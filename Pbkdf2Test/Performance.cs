using System.Security.Cryptography;
using System.Text;
using Pbkdf2;
using System;

namespace Pbkdf2Test;

[TestFixture]
public class Performance
{
#if DEBUG
    [Test]
    public void Benchmark()
    {
        var algorithmName = "SHA512";
        var passwordBytes = Encoding.UTF8.GetBytes("password");
        var saltBytes = Encoding.UTF8.GetBytes("salt");
        int iterations = 10_000;
        var desiredKeyLength = 32 << 10;

        var t0 = DateTime.UtcNow;
        var reference = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, saltBytes, iterations, new HashAlgorithmName(algorithmName), desiredKeyLength);
        var t1 = DateTime.UtcNow;
        var testedImplementation = Pbkdf2.Pbkdf2.HashData("HMAC" + algorithmName, passwordBytes, saltBytes, iterations, desiredKeyLength);
        var t2 = DateTime.UtcNow;
        var dtDotNet = t1 - t0;
        var dtMe = t2 - t1;
    }
#endif
}