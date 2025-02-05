﻿using System;
using System.IO;
using System.Security.Cryptography;

namespace iOS.Backup.Decrypt.Library
{
    public class AesEncryptionProvider
    {
        public byte[] DecryptAes(byte[] inputData, byte[] key, CipherMode mode)
        {
            if (inputData == null || inputData.Length == 0)
                throw new ArgumentNullException(nameof(inputData));
            
            using (var inputStream = new MemoryStream(inputData))
            {
                using (var outputStream = new MemoryStream())
                {
                    DecryptAes(inputStream, key, mode, outputStream);
                    return outputStream.ToArray();
                }
            }
        }

        public void DecryptAes(string inputFilename, byte[] key, CipherMode mode, string outputFilename)
        {
            if (string.IsNullOrWhiteSpace(inputFilename))
                throw new ArgumentNullException(nameof(inputFilename));
            if (string.IsNullOrWhiteSpace(outputFilename))
                throw new ArgumentNullException(nameof(outputFilename));
            
            using (var inputStream = new FileStream(inputFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                using (var outputStream =
                       new FileStream(outputFilename, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    DecryptAes(inputStream, key, mode, outputStream);
                }
            }            
        }
        
        // If CBC mode:
        // The file on the device was already padded out using pkcs7.
        // We need to manually validate and remove the padding after decryption.
        private void DecryptAes(Stream inputStream, byte[] key, CipherMode mode, Stream outputStream)
        {
            if (inputStream == null || inputStream.Length == 0)
                throw new ArgumentNullException(nameof(inputStream));
            if (mode == CipherMode.CBC && inputStream.Length % 16 != 0)
                throw new ArgumentOutOfRangeException(nameof(inputStream));
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));            
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            using (Aes aes = Aes.Create())
            {
                var m_IV = new byte[16];

                aes.Mode = mode;
                aes.KeySize = key.Length * 8;
                aes.Key = key;
                aes.BlockSize = m_IV.Length * 8;
                aes.IV = m_IV;
                // Manually remove pkcs7 padding!
                aes.Padding = PaddingMode.None; 

                using (ICryptoTransform transform = aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(inputStream, transform, CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
                
                if (mode == CipherMode.CBC)
                {
                    // Manually remove pkcs7 padding!
                    ValidateAndRemovePkcs7Padding(outputStream);
                }                
            }
        }

        private void ValidateAndRemovePkcs7Padding(Stream outputStream)
        {
            if (outputStream.Length > 1)
            {
                outputStream.Position = outputStream.Length - 1;
                var padLength = outputStream.ReadByte();
                if (padLength > 0 && padLength <= 16 && padLength < outputStream.Length)
                {
                    outputStream.Position = outputStream.Length - padLength;
                    var padBytes = new byte[padLength];
                    if (outputStream.Read(padBytes, 0, padLength) != padLength)
                    {
                        throw new CryptographicException("Failed to read padding.");
                    }

                    foreach (var b in padBytes)
                    {
                        if (b != padLength)
                        {
                            throw new CryptographicException("Padding is invalid.");
                        }
                    }

                    outputStream.Position = outputStream.Length - padLength - 1;
                    outputStream.SetLength(outputStream.Length - padLength);
                }
            }            
        }
    }
}
