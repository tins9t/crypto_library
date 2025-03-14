using System.Security.Cryptography;
using System.Text;
using Crypto_library;

// Cryptographic random number generator (CRNG)
byte[] key = new byte[32]; // 256-bit key
Console.WriteLine("Key: "+Convert.ToBase64String(key));
using (var rng = RandomNumberGenerator.Create()) {
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
using (var sha512 = SHA512.Create()) {
    byte[] hash = sha512.ComputeHash(Encoding.UTF8.GetBytes(plainText));
    Console.WriteLine("SHA-512: " + Convert.ToBase64String(hash));
}

// Message Authentication Code (MAC)
var macText = "Authenticate me!";
byte[] mac;
byte[] mac2;
using (var hmac = new HMACSHA256(key)) {
    mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(macText));
    Console.WriteLine("HMAC-SHA256: " + Convert.ToBase64String(mac));
}
using (var hmac = new HMACSHA256(key)) {
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

// RSA (Rivest–Shamir–Adleman)

// Key derivation

