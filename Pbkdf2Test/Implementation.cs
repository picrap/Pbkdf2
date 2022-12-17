using System.Linq;
using NUnit.Framework;
using Pbkdf2;

namespace Pbkdf2Test;

[TestFixture]
public class Implementation
{
    [Test]
    [TestCase(0, 1)]
    [TestCase(1, 1)]
    [TestCase(2, 1)]
    [TestCase(19, 1)]
    [TestCase(20, 1)]
    [TestCase(21, 1)]
    [TestCase(19, 3)]
    [TestCase(1, 38)]
    [TestCase(1, 98)]
    [TestCase(1, 99)]
    [TestCase(1, 100)]
    public void ByteOffset(int start, int count)
    {
        var password = new byte[] { 6, 7, 8, 9 };
        var salt = new byte[] { 12, 13, 14, 15, 16, 17 };
        var iterations = 2;
        var algorithmName = "HMACSHA1";
        var fullRange = Pbkdf2.Pbkdf2.HashData(algorithmName, password, salt, iterations, 1000);
        using var kdf = new HmacPbkdf2DeriveBytes(algorithmName, password, salt, iterations);
        var requestedRange = kdf.GetBytes(start, count);
        Assert.IsTrue(fullRange.Skip(start).Take(count).SequenceEqual(requestedRange));
    }
}