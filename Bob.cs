using System.Security.Cryptography;
using System.Text;

namespace Crypto_library;

using System.Security.Cryptography;

public class Bob
{
    private ECDiffieHellmanCng bob;
    public byte[] PublicKey { get; private set; }
    private byte[] sharedKey;

    public Bob()
    {
        bob = new ECDiffieHellmanCng();
        bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        bob.HashAlgorithm = CngAlgorithm.Sha256;
        PublicKey = bob.PublicKey.ToByteArray();
    }

    public void DeriveSharedKey(byte[] alicePublicKey)
    {
        CngKey aliceKey = CngKey.Import(alicePublicKey, CngKeyBlobFormat.EccPublicBlob);
        sharedKey = bob.DeriveKeyMaterial(aliceKey);
        Console.WriteLine("Bob Shared Key: " + Convert.ToBase64String(sharedKey));
    }

    public string DecryptMessage(byte[] encryptedData, byte[] iv)
    {
        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = sharedKey;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(encryptedData, 0, encryptedData.Length);
                cs.Close();
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }
    }
}