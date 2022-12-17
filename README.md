# Pbkdf2

The same as [.NET implementation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes), but with much more extensibility, such as other hashes and the ability to replace any algorithm part (at your own risk).
Available as a [![NuGet](https://img.shields.io/nuget/v/Pbkdf2.svg?style=flat-square)](https://www.nuget.org/packages/Pbkdf2) package.

# How to use it

## Simple way

```csharp
var saltBytes = new byte [] {1, 2, 3, 4, 5}; // use much more than this!
var hash = Pbkdf2.HashData("HMACSHA512", "my password", saltBytes, 
           100000 /* iterations */, 32 /* hash size in bytes */);
```

## Full way

```csharp
var saltBytes = new byte [] {1, 2, 3, 4, 5}; // use much more than this!
using var pbkdf2 = new HmacPbkdf2DeriveBytes("HMACSHA512", "my password", saltBytes, 
           100000 /* iterations */);
var hash = pbkdf2.GetBytes(32 /* hash size in bytes */);
```

## Derive

All methods can be overriden so any part of hash can be replaced.
The idea is to avoid being brute forced by an ASIC, for example by simply adding a user block manipulation at `PseudoRandomFunction` or `ComputeBlockIteration`.

Currently there are three classes:
- `Pbkdf2DeriveBytes` is the abstract class which requires only to add a pseudo-random function
- `HmacPbkdf2DeriveBytes` is an implementation of `Pbkdf2DeriveBytes`, specific to use HMACs.
- `ParallelHmacPbkdf2DeriveBytes` is an implementation of `Pbkdf2DeriveBytes`, specific to use HMACs and work in parallel (using PLINQ).

# References

- [RFC 2898](https://www.rfc-editor.org/rfc/rfc2898): the reference
- [.NET implementation documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes): our implementation works the same
- [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2): a human-readable description
