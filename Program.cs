using System.Security.Cryptography;
using System.Text;
using Crypto_library;
using NSec.Cryptography;


// Cryptographic random number generator (CRNG)
byte[] key = new byte[32]; // 256-bit key
Console.WriteLine("Key: " + Convert.ToBase64String(key));
using (var rng = RandomNumberGenerator.Create())
{
    rng.GetBytes(key);
}

Console.WriteLine(Convert.ToBase64String(key));

// Shared-key (symmetric) cipher
string publicKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
string plainText = "This is a secret message!";

// Encrypt
string encryptedText = AesExample.Encrypt(plainText, publicKey, key);
Console.WriteLine("Encrypted: " + encryptedText);

// Decrypt
string decryptedText = AesExample.Decrypt(encryptedText, publicKey, key);
Console.WriteLine("Decrypted: " + decryptedText);

// Hashing
using (var sha512 = SHA512.Create())
{
    byte[] hash = sha512.ComputeHash(Encoding.UTF8.GetBytes(plainText));
    Console.WriteLine("SHA-512: " + Convert.ToBase64String(hash));
}

// Message Authentication Code (MAC)
var macText = "Authenticate me!";
byte[] mac;
byte[] mac2;
using (var hmac = new HMACSHA256(key))
{
    mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(macText));
    Console.WriteLine("HMAC-SHA256: " + Convert.ToBase64String(mac));
}

using (var hmac = new HMACSHA256(key))
{
    mac2 = hmac.ComputeHash(Encoding.UTF8.GetBytes(macText));
    Console.WriteLine("HMAC-SHA256: " + Convert.ToBase64String(mac2));
}

if (mac.ToString().Equals(mac2.ToString()))
{
    Console.WriteLine("Success!");
}
else Console.WriteLine("Fail!");

// Diffie-Hellman key exchange
Alice alice = new Alice();
Bob bob = new Bob();

alice.DeriveSharedKey(bob.PublicKey);
bob.DeriveSharedKey(alice.PublicKey);
string secretMessage = "This is a TOP secret message!";
var (encryptedMessage, iv) = alice.EncryptMessage(secretMessage);
string decryptedMessage = bob.DecryptMessage(encryptedMessage, iv);
Console.WriteLine("Encrypted message: " + Convert.ToBase64String(encryptedMessage));
Console.WriteLine("Decrypted message: " + decryptedMessage);

// Digital signatures
Console.WriteLine("\nDigital signatures:");
var algorithm = SignatureAlgorithm.Ed25519;
using var edKey = Key.Create(algorithm);
Console.WriteLine("\nMessage to encrypt: Use the Force, Luke!");
var data = "Use the Force, Luke!"u8.ToArray();
Console.WriteLine("\nEncrypted data: " + Convert.ToBase64String(data));

var signature = algorithm.Sign(edKey, data);
Console.WriteLine("\nSignature: " + Convert.ToBase64String(signature));
Console.WriteLine("Verifying signature...");
if (algorithm.Verify(edKey.PublicKey, data, signature))
{
    Console.WriteLine("\nVerification successful!");
}

// RSA (Rivest–Shamir–Adleman)
Console.WriteLine("\nRSA:");
using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
{
    var rsaExample = new RsaExample();
    var dataToEncrypt = "Hej Rasmus, læser du dette her?"u8.ToArray();
    Console.WriteLine("Data to encrypt: " + Convert.ToBase64String(dataToEncrypt));
    var encryptedData = rsaExample.RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);
    Console.WriteLine("Encrypted data: " + Convert.ToBase64String(encryptedData));
    var decryptedData = rsaExample.RSADecrypt(encryptedData, RSA.ExportParameters(true), false);
    Console.WriteLine("\nRSA decrypted data: " + Convert.ToBase64String(decryptedData));
    Console.WriteLine("Human readable: " + Encoding.UTF8.GetString(decryptedData));
}

// Key derivation
Console.WriteLine("\nKey derivation:");
string password = "securepassword";
Console.WriteLine("\nPassword: " + password);
byte[] salt = new byte[16];
Console.WriteLine("\nSalt: " + Convert.ToBase64String(salt));
RandomNumberGenerator.Fill(salt);

using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA512))
{
    byte[] pbkdf2Key = pbkdf2.GetBytes(32);
    Console.WriteLine("Derived key: "+Convert.ToBase64String(pbkdf2Key));
}