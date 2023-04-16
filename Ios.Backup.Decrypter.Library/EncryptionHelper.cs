using System;
using System.IO;
using System.Security.Cryptography;

namespace Ios.Backup.Decrypter.Library
{
    public static class EncryptionHelper
    {
        public static byte[] DecryptAES(byte[] inputData, byte[] key, CipherMode mode)
        {
            using (var inputStream = new MemoryStream(inputData))
            {
                using (var outputStream = new MemoryStream())
                {
                    DecryptAES(inputStream, key, mode, outputStream);
                    return outputStream.ToArray();
                }
            }
        }
        
        public static void DecryptAES(Stream inputStream, byte[] key, CipherMode mode, Stream outputStream)
        {
            // Check arguments.
            if (inputStream == null || inputStream.Length <= 0)
                throw new ArgumentNullException(nameof(inputStream));
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                var m_IV = new byte[16];

                rijAlg.Mode = mode;
                rijAlg.KeySize = key.Length * 8;
                rijAlg.Key = key;
                rijAlg.BlockSize = m_IV.Length * 8;
                rijAlg.IV = m_IV;
                rijAlg.Padding = PaddingMode.Zeros;

                using (ICryptoTransform decryptor = rijAlg.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
        }
    }
}
