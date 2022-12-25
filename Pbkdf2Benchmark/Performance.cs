using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace Pbkdf2Benchmark;

public class Performance
{
    private const string AlgorithmName = "SHA512";
    readonly byte[] _passwordBytes = Encoding.UTF8.GetBytes("password");
    readonly byte[] _saltBytes = Encoding.UTF8.GetBytes("some salt in there, because that’s what people do");

    [Params(10_000)] public int Iterations { get; set; }
    [Params(512/8, 32 << 10)] public int DesiredKeyLength { get; set; }

    [Benchmark]
    public byte[] DotNet() => Rfc2898DeriveBytes.Pbkdf2(_passwordBytes, _saltBytes, Iterations, new HashAlgorithmName(AlgorithmName), DesiredKeyLength);

    [Benchmark]
    public byte[] Pbkdf2() => global::Pbkdf2.Pbkdf2.HashData("HMAC" + AlgorithmName, _passwordBytes, _saltBytes, Iterations, DesiredKeyLength);

    [Benchmark]
    public byte[] ParallelPbkdf2() => global::Pbkdf2.Pbkdf2.ParallelHashData(() => new HMACSHA512(_passwordBytes), _saltBytes, Iterations, DesiredKeyLength);
}
