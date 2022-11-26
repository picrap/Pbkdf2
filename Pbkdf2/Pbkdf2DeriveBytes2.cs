using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Pbkdf2;

#if NET6_0_OR_GREATER

public abstract class Pbkdf2DeriveBytes2 : DeriveBytes
{
    protected byte[] Salt { get; }
    protected int Iterations { get; }

    protected abstract int BlockLength { get; }

    protected Pbkdf2DeriveBytes2(byte[] salt, int iterations)
    {
        Salt = salt;
        Iterations = iterations;
    }

    public override byte[] GetBytes(int desiredLength)
    {
        var derivedKey = new byte[desiredLength];
        var blocksCount = desiredLength / BlockLength;
        if (desiredLength % BlockLength != 0)
            blocksCount++;

        var blockOffset = 0;
        for (int blockNumber = 1; blockNumber <= blocksCount; blockNumber++)
        {
            var block = ComputeBlock(Salt, Iterations, blockNumber);
            var remainingLength = Math.Min(block.Length, derivedKey.Length - blockOffset);
            Buffer.BlockCopy(block, 0, derivedKey, blockOffset, remainingLength);
            blockOffset += BlockLength;
        }

        return derivedKey;
    }

    public override void Reset()
    {
    }

    protected virtual byte[] ComputeBlock(byte[] salt, int count, int blockNumber)
    {
        var block = new byte[BlockLength];
        var blockSpan = block.AsSpan();
        Span<byte> currentBlockIterationSpan = stackalloc byte[BlockLength];
        for (int iterationNumber = 1; iterationNumber <= count; iterationNumber++)
        {
            ComputeBlockIteration(currentBlockIterationSpan, salt, blockNumber, iterationNumber, currentBlockIterationSpan);
            CombineBlockIteration(blockSpan, currentBlockIterationSpan);
        }

        return block;
    }

    protected virtual void ComputeBlockIteration(ReadOnlySpan<byte> currentBlockIteration, byte[] salt, int blockNumber, int blockIterationNumber, Span<byte> blockIteration)
    {
        switch (blockIterationNumber)
        {
            case 1:
                ComputeBlockFirstIteration(salt, blockNumber, blockIteration);
                break;
            default:
                ComputeBlockNextIteration(currentBlockIteration, blockIteration);
                break;
        }
    }

    protected virtual void ComputeBlockNextIteration(ReadOnlySpan<byte> currentBlockIteration, Span<byte> blockIteration)
    {
        PseudoRandomFunction(currentBlockIteration, blockIteration);
    }

    protected virtual void ComputeBlockFirstIteration(byte[] salt, int blockNumber, Span<byte> blockIteration)
    {
        // TODO: better
        PseudoRandomFunction(salt.Concat(GetInt32BigEndian(blockNumber)).ToArray(), blockIteration);
    }

    protected virtual byte[] GetInt32BigEndian(int i)
    {
        if (BitConverter.IsLittleEndian)
            return BitConverter.GetBytes(i).Reverse().ToArray();
        return BitConverter.GetBytes(i);
    }

    protected virtual void CombineBlockIteration(Span<byte> currentBlockIteration, ReadOnlySpan<byte> newBlockIteration)
    {
        var byteIndex = 0;
        foreach (var b in newBlockIteration)
            currentBlockIteration[byteIndex++] ^= b;
    }

    protected abstract void PseudoRandomFunction(ReadOnlySpan<byte> input, Span<byte> output);
}

#endif
