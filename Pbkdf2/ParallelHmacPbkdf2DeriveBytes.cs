using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Pbkdf2;

#if NET6_0_OR_GREATER

public class ParallelHmacPbkdf2DeriveBytes : Pbkdf2DeriveBytes
{
    private readonly Func<byte[], HMAC> _createHmac;
    private readonly byte[] _password;

    private int _blockLength;
    protected override int BlockLength => _blockLength;

    private readonly Queue<HMAC> _hmacs = new();

    public ParallelHmacPbkdf2DeriveBytes(string hashAlgorithmName, byte[] password, byte[] salt, int iterations)
        : this(p => Pbkdf2.CreateHMAC(hashAlgorithmName, p), password, salt, iterations)
    {
    }

    public ParallelHmacPbkdf2DeriveBytes(HashAlgorithmName hashAlgorithmName, byte[] password, byte[] salt,
        int iterations)
        : this(hashAlgorithmName.Name, password, salt, iterations)
    {
    }

    public ParallelHmacPbkdf2DeriveBytes(Func<byte[], HMAC> createHmac, byte[] password, byte[] salt, int iterations)
        : base(salt, iterations)
    {
        _createHmac = createHmac;
        _password = password;
        UsingHmac(h => _blockLength = h.HashSize / 8);
    }

    protected override void Dispose(bool disposing)
    {
        foreach (var hmac in _hmacs)
            hmac.Dispose();
        _hmacs.Clear();
    }

    private HMAC PullHmac()
    {
        lock (_hmacs)
        {
            if (_hmacs.Count > 0)
                return _hmacs.Dequeue();
            return _createHmac(_password);
        }
    }

    private void PushHmac(HMAC hmac)
    {
        lock (_hmacs)
            _hmacs.Enqueue(hmac);
    }

    protected override IEnumerable<Tuple<int, byte[]>> ComputeBlocks(int firstBlockNumber, int blocksCount, object context)
    {
        return Enumerable.Range(firstBlockNumber, blocksCount).AsParallel()
            .Select(b => Tuple.Create(b, ComputeBlock(Salt, Iterations, b, context)));
    }

    private TResult UsingHmac<TResult>(Func<HMAC, TResult> func)
    {
        var hmac = PullHmac();
        try
        {
            return func(hmac);
        }
        finally
        {
            PushHmac(hmac);
        }
    }

    protected override byte[] ComputeBlock(byte[] salt, int count, int blockNumber, object context)
    {
        return UsingHmac(hmac => base.ComputeBlock(salt, count, blockNumber, hmac));
    }

    protected override byte[] PseudoRandomFunction(byte[] data, object context)
    {
        var hmac = (HMAC)context;
        return hmac.ComputeHash(data);
    }
}

#endif
