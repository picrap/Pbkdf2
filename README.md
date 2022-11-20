# Pbkdf2

The same as [.NET implementation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes), but with much more extensibility, such as other hashes and the ability to replace any algorithm part (at your own risk).

# How to use it

## Simple way

```csharp
var saltBytes = new byte [] {1, 2, 3, 4, 5}; // use much more than this!
var hash = Pbkdf2.Compute("HMACSHA512", "my password", saltBytes, 
           100_000 /* iterations */, 32 /* hash size in bytes */);
```

## Full way

```csharp
var saltBytes = new byte [] {1, 2, 3, 4, 5}; // use much more than this!
using var pbkdf2 = new HMACPbkdf2DeriveBytes("HMACSHA512", "my password", saltBytes, 
           100_000 /* iterations */);
var hash = pbkdf2.GetBytes(32 /* hash size in bytes */);
```

## Derive

All methods can be overriden so any part of hash can be replaced.
The idea is to avoid being brute forced by an ASIC.

# References

- [RFC 2898](https://www.rfc-editor.org/rfc/rfc2898): the reference
- [.NET implementation documentation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes): our implementation works the same
- [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2): a human-readable description
