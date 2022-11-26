
using System.Text;

var algorithmName = "SHA512";
var passwordBytes = Encoding.UTF8.GetBytes("password");
var saltBytes = Encoding.UTF8.GetBytes("salt");
int iterations = 100_000;
var desiredKeyLength = 32 << 10;

var testedImplementation = Pbkdf2.Pbkdf2.HashData("HMAC" + algorithmName, passwordBytes, saltBytes, iterations, desiredKeyLength);
