using System.Security.Cryptography;
using System.Text;

namespace Crypto_library;

 public static class AesExample
    {
        public static string Decrypt(string cipherText, string publicKey, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = Convert.FromBase64String(publicKey);
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
                using (var decryptor = aes.CreateDecryptor())
                {
                    return Encoding.UTF8.GetString(decryptor.TransformFinalBlock(cipherTextBytes, 0,
                        cipherTextBytes.Length));
                }
            }
        }

        public static string Encrypt(string plainText, string publicKey, byte[] key)
        {
            using (var aes = Aes.Create()) {
                aes.Key = key;
                aes.IV = Convert.FromBase64String(publicKey);
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                using (var encryptor = aes.CreateEncryptor()) {
                    return Convert.ToBase64String(encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length));
                }
            }
        }
    }