using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Pbkdf2;

public abstract class Pbkdf2DeriveBytes : DeriveBytes
{
    protected byte[] Salt { get; }
    protected int Iterations { get; }

    protected abstract int BlockLength { get; }

    protected Pbkdf2DeriveBytes(byte[] salt, int iterations)
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
        var currentBlockIteration = new byte[BlockLength];
        for (int iterationNumber = 1; iterationNumber <= count; iterationNumber++)
        {
            currentBlockIteration = ComputeBlockIteration(currentBlockIteration, salt, blockNumber, iterationNumber);
            CombineBlockIteration(block, currentBlockIteration);
        }

        return block;
    }

    protected virtual byte[] ComputeBlockIteration(byte[] currentBlockIteration, byte[] salt, int blockNumber, int blockIterationNumber)
    {
        return blockIterationNumber switch
        {
            1 => ComputeBlockFirstIteration(salt, blockNumber),
            _ => ComputeBlockNextIteration(currentBlockIteration)
        };
    }

    protected virtual byte[] ComputeBlockNextIteration(byte[] currentBlockIteration)
    {
        return PseudoRandomFunction(currentBlockIteration);
    }

    protected virtual byte[] ComputeBlockFirstIteration(byte[] salt, int blockNumber)
    {
        return PseudoRandomFunction(salt, GetInt32BigEndian(blockNumber));
    }

    protected virtual byte[] GetInt32BigEndian(int i)
    {
        if (BitConverter.IsLittleEndian)
            return BitConverter.GetBytes(i).Reverse().ToArray();
        return BitConverter.GetBytes(i);
    }

    protected virtual void CombineBlockIteration(byte[] currentBlockIteration, byte[] newBlockIteration)
    {
        for (int byteIndex = 0; byteIndex < currentBlockIteration.Length; byteIndex++)
            currentBlockIteration[byteIndex] ^= newBlockIteration[byteIndex];
    }

    protected abstract byte[] PseudoRandomFunction(byte[] data);
    protected virtual byte[] PseudoRandomFunction(IEnumerable<byte> data) => PseudoRandomFunction(data.ToArray());
    protected virtual byte[] PseudoRandomFunction(params byte[][] data) => PseudoRandomFunction(data.SelectMany(d => d));
}