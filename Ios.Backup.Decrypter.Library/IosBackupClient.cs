﻿using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Claunia.PropertyList;
using Ios.Backup.Extractor;
using Microsoft.Data.Sqlite;

namespace Ios.Backup.Decrypter.Library
{
    // TODO: Extract interface, and also inject deps properly.
    public class IosBackupClient : IDisposable
    {
        private readonly string _tempFilePath;
        private readonly ManifestRepository _repository;
        private readonly string _backupDir;
        private readonly string _passPhrase;
        private KeyBag _keybag;
        private bool _unlocked;

        private string ManifestFile => Path.Combine(_backupDir, "Manifest.plist");
        private string ManifestDb => Path.Combine(_backupDir, "Manifest.db");

        // TODO: Need better handling of the password. Once it becomes a string, it's there for all to see in memory.
        public IosBackupClient(string backupDir, string passPhrase)
        {
            _backupDir = backupDir;
            _passPhrase = passPhrase;
            _tempFilePath = GetTemporaryDirectory();
            _repository = new ManifestRepository(_tempFilePath);

        }

        /// <summary>
        /// Extracts a file like a sqlite db
        /// </summary>
        /// <param name="path">iOS path to file</param>
        /// <param name="outputFileName">Path to save file</param>
        public void ExtractFile(string path, string outputFileName)
        {
            var bytes = ExtractFileAsBytes(path);
            File.WriteAllBytes(outputFileName, bytes);
        }

        private void Init()
        {
            if (_unlocked)
            {
                return;
            }

            FileInfo file = new FileInfo(ManifestFile);
            NSDictionary rootDict = (NSDictionary)PropertyListParser.Parse(file);

            NSData backupKeyBag = (NSData)rootDict.ObjectForKey("BackupKeyBag");
            _keybag = new KeyBag(backupKeyBag);

            NSData manifestKeyObject = (NSData)rootDict.ObjectForKey("ManifestKey");

            if (manifestKeyObject == null)
            {
                throw new Exception("Could not find ManifestKey. Is this an encrypted backup?");
            }

            var manifestKey = manifestKeyObject.Bytes.Skip(4).ToArray();
            var manifestClass = (int)StructConverter.Unpack("<l", manifestKeyObject.Bytes.Take(4).ToArray())[0];

            _keybag.UnlockWithPassphrase(_passPhrase);


            var key = _keybag.UnwrapKeyForClass(manifestClass, manifestKey);


            var encryptedDb = File.ReadAllBytes(ManifestDb);

            var decryptedData = EncryptionHelper.DecryptAES(encryptedDb, key, CipherMode.CBC);
            File.WriteAllBytes(Path.Combine(_tempFilePath, "Manifest.db"), decryptedData);


            if (!_repository.OpenTempDb())
            {
                throw new Exception("Manifest.db file does not seem to be the right format!");
            }

            _unlocked = true;
        }

        private byte[] ExtractFileAsBytes(string path)
        {
            Init();
            var file = _repository.GetFile(path);
            return ExtractFileAsBytes(file);
        }

        private byte[] ExtractFileAsBytes(DBFile file)
        {
            var plist = (NSDictionary) PropertyListParser.Parse(file.file);
            var objects = (NSArray) plist.Get("$objects");

            var top = (NSDictionary) plist.Get("$top");
            var root = (UID) top["root"];
            var objectsItem = (int) root.ToUInt64();

            var fileData = (NSDictionary) objects[objectsItem];

            var protectionClass = (NSNumber) fileData["ProtectionClass"];

            if (!fileData.ContainsKey("EncryptionKey"))
            {
                return null; //This file is not encrypted; either a directory or empty.
            }

            var keyId = (UID) fileData["EncryptionKey"];

            var encryptionKeyArray = (NSDictionary) objects[(int) keyId.ToUInt64()];

            var encryptionKeyData = (NSData) encryptionKeyArray["NS.data"];

            var encryptionKey = encryptionKeyData.Bytes.Skip(4).ToArray();

            var innerKey = _keybag.UnwrapKeyForClass(protectionClass.ToInt(), encryptionKey);

            var fileNameInBackup = Path.Combine(_backupDir, file.fileID[new Range(0, 2)], file.fileID);

            // TODO: Open a file stream and pass that to be decrypted
            var encryptedData = File.ReadAllBytes(fileNameInBackup);

            var decryptedData = EncryptionHelper.DecryptAES(encryptedData, innerKey, CipherMode.CBC);

            return RemovePadding(decryptedData);
        }
        
        private byte[] RemovePadding(byte[] decryptedData, int blocksize = 16)
        {
            var n = decryptedData.Last();

            if (n > blocksize || n > decryptedData.Length)
            {
                throw new Exception("Invalid CBC padding");
            }

            return decryptedData[new Range(0, decryptedData.Length - n)];
        }

        private string GetTemporaryDirectory()
        {
            string tempFolder = Path.GetTempFileName();
            File.Delete(tempFolder);
            Directory.CreateDirectory(tempFolder);

            return tempFolder;
        }

        public void Dispose()
        {
            if (!string.IsNullOrWhiteSpace(_tempFilePath) && Directory.Exists(_tempFilePath))
            {
                SqliteConnection.ClearAllPools();
                Directory.Delete(_tempFilePath, true);
            }
        }
    }
}
