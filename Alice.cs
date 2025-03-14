using System.Security.Cryptography;
using System.Text;

namespace Crypto_library;

public class Alice
{
    private ECDiffieHellmanCng alice;
    public byte[] PublicKey { get; private set; }
    private byte[] sharedKey;

    public Alice()
    {
        alice = new ECDiffieHellmanCng();
        alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        alice.HashAlgorithm = CngAlgorithm.Sha256;
        PublicKey = alice.PublicKey.ToByteArray();
    }

    public void DeriveSharedKey(byte[] bobPublicKey)
    {
        CngKey bobKey = CngKey.Import(bobPublicKey, CngKeyBlobFormat.EccPublicBlob);
        sharedKey = alice.DeriveKeyMaterial(bobKey);
        Console.WriteLine("Alice Shared Key: " + Convert.ToBase64String(sharedKey));
    }


    public (byte[] EncryptedMessage, byte[] IV) EncryptMessage(string message)
    {
        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = sharedKey;
            byte[] iv = aes.IV;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] plaintext = Encoding.UTF8.GetBytes(message);
                cs.Write(plaintext, 0, plaintext.Length);
                cs.Close();
                return (ms.ToArray(), iv);
            }
        }
    }
}