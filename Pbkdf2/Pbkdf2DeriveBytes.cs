using System.Security.Cryptography;

namespace Pbkdf2;

public abstract class Pbkdf2DeriveBytes : DeriveBytes
{
    protected byte[] Salt { get; }
    protected int Count { get; }
    protected int DesiredKeyLength { get; }

    protected abstract int BlockLength { get; }

    protected Pbkdf2DeriveBytes(byte[] salt, int count, int desiredKeyLength)
    {
        Salt = salt;
        Count = count;
        DesiredKeyLength = desiredKeyLength;
    }

    public override byte[] GetBytes(int cb)
    {
        var derivedKey = new byte[DesiredKeyLength];
        var blocksCount = DesiredKeyLength / BlockLength;
        if (DesiredKeyLength % BlockLength != 0)
            blocksCount++;

        var blockOffset = 0;
        for (int blockIndex = 0; blockIndex < blocksCount; blockIndex++)
        {
            var block = ComputeBlock(Salt, Count, blockIndex);
            var remainingLength = Math.Min(block.Length, derivedKey.Length - blockOffset);
            Buffer.BlockCopy(block, 0, derivedKey, blockOffset, remainingLength);
        }

        return derivedKey;
    }

    public override void Reset()
    {
    }

    protected virtual byte[] ComputeBlock(byte[] salt, int count, int blockIndex)
    {
        var block = new byte[BlockLength];
        for (int iteration = 0; iteration < count; iteration++)
        {
            var iterationBlock = ComputeBlockIteration(block, salt, blockIndex, iteration);
            CombineBlockIteration(block, iterationBlock);
        }

        return block;
    }

    protected virtual byte[] ComputeBlockIteration(byte[] previousIteration, byte[] salt, int blockIndex, int blockIteration)
    {
        if (blockIteration == 0)
            return PseudoRandomFunction(salt, GetInt32BigEndian(blockIndex));
        return PseudoRandomFunction(previousIteration);
    }

    protected virtual byte[] GetInt32BigEndian(int i)
    {
        if (BitConverter.IsLittleEndian)
            return BitConverter.GetBytes(i).Reverse().ToArray();
        return BitConverter.GetBytes(i);
    }

    protected virtual void CombineBlockIteration(byte[] previousIteration, byte[] newBlockIteration)
    {
        for (int byteIndex = 0; byteIndex < previousIteration.Length; byteIndex++)
            previousIteration[byteIndex] ^= newBlockIteration[byteIndex];
    }

    protected abstract byte[] PseudoRandomFunction(byte[] data);
    protected virtual byte[] PseudoRandomFunction(IEnumerable<byte> data) => PseudoRandomFunction(data.ToArray());
    protected virtual byte[] PseudoRandomFunction(params byte[][] data) => PseudoRandomFunction(data.SelectMany(d => d));
}