﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Xml.Schema;

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

    public override byte[] GetBytes(int desiredLength) => GetBytes(0, desiredLength);

    public byte[] GetBytes(int offset, int count)
    {
        var derivedKey = new byte[count];
        GetBytes(offset, derivedKey, 0, count);
        return derivedKey;
    }

    public void GetBytes(int bytesOffset, byte[] target, int targetOffset, int count)
    {
        if (targetOffset + count > target.Length)
            throw new ArgumentException("target must be big enough to hold result");
        if (bytesOffset < 0)
            throw new ArgumentException($"{nameof(bytesOffset)} must be positive");
        if (count < 0)
            throw new ArgumentException($"{nameof(count)} must be positive (you dumbass)");
        if (count == 0)
            return; // Boom! Done!

        var firstBlockIndex = bytesOffset / BlockLength;
        var lastBlockIndex = (bytesOffset + count - 1) / BlockLength;
        var blocksCount = lastBlockIndex - firstBlockIndex + 1;

        var bytesEnd = bytesOffset + count;
        foreach (var numberedBlock in ComputeBlocks(firstBlockIndex + 1, blocksCount, null))
        {
            var blockIndex = numberedBlock.Item1 - 1;
            var blockData = numberedBlock.Item2;
            var blockOffset = blockIndex * BlockLength;
            var nextBlockOffset = blockOffset + BlockLength;
            var blockStartByte = Math.Max(bytesOffset - blockOffset, 0);
            var blockEndByte = Math.Min(bytesEnd, nextBlockOffset) - blockOffset;
            var targetByteOffset = Math.Max((blockIndex - firstBlockIndex) * BlockLength - bytesOffset % BlockLength, 0);
            Buffer.BlockCopy(blockData, blockStartByte, target, targetOffset + targetByteOffset, blockEndByte - blockStartByte);
        }
    }

    protected virtual IEnumerable<Tuple<int, byte[]>> ComputeBlocks(int firstBlockNumber, int blocksCount, object context)
    {
        return Enumerable.Range(firstBlockNumber, blocksCount).Select(b => Tuple.Create(b, ComputeBlock(Salt, Iterations, b, context)));
    }

    public override void Reset()
    {
    }

    protected virtual byte[] ComputeBlock(byte[] salt, int count, int blockNumber, object context)
    {
        var block = new byte[BlockLength];
        var currentBlockIteration = new byte[BlockLength];
        for (int iterationNumber = 1; iterationNumber <= count; iterationNumber++)
        {
            currentBlockIteration = ComputeBlockIteration(currentBlockIteration, salt, blockNumber, iterationNumber, context);
            CombineBlockIteration(block, currentBlockIteration);
        }

        return block;
    }

    protected virtual byte[] ComputeBlockIteration(byte[] currentBlockIteration, byte[] salt, int blockNumber, int blockIterationNumber, object context)
    {
        return blockIterationNumber switch
        {
            1 => ComputeBlockFirstIteration(salt, blockNumber, context),
            _ => ComputeBlockNextIteration(currentBlockIteration, context)
        };
    }

    protected virtual byte[] ComputeBlockNextIteration(byte[] currentBlockIteration, object context)
    {
        return PseudoRandomFunction(currentBlockIteration, context);
    }

    protected virtual byte[] ComputeBlockFirstIteration(byte[] salt, int blockNumber, object context)
    {
        var firstBlock = new byte[salt.Length + 4];
        Buffer.BlockCopy(salt, 0, firstBlock, 0, salt.Length);
        Buffer.BlockCopy(GetInt32BigEndian(blockNumber), 0, firstBlock, salt.Length, 4);
        return PseudoRandomFunction(firstBlock, context);
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

    protected abstract byte[] PseudoRandomFunction(byte[] data, object context);
}
