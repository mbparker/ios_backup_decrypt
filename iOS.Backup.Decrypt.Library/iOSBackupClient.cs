using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Claunia.PropertyList;
using iOS.Backup.Decrypt.Library.Repositories;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace iOS.Backup.Decrypt.Library
{
    // TODO: Extract interface, and also inject deps properly.
    public class iOSBackupClient : IDisposable
    {
        private readonly string workingCopyPath;
        private readonly AesEncryptionProvider aesEncryptionProvider;
        private readonly ManifestRepository manifestRepository;
        private readonly string sourceBackupPath;
        private readonly string sourceBackupPassword;
        private KeyBag keybag;
        private bool initialized;

        private string ManifestFile => Path.Combine(sourceBackupPath, "Manifest.plist");
        private string ManifestDb => Path.Combine(sourceBackupPath, "Manifest.db");

        // TODO: Need better handling of the password. Once it becomes a string, it's there for all to see in memory.
        public iOSBackupClient(string sourceBackupPath, string sourceBackupPassword)
        {
            this.sourceBackupPath = sourceBackupPath;
            this.sourceBackupPassword = sourceBackupPassword;
            workingCopyPath = GetTemporaryDirectory();
            manifestRepository = new ManifestRepository(workingCopyPath);
            aesEncryptionProvider = new AesEncryptionProvider();

        }
        
        public void Dispose()
        {
            if (!string.IsNullOrWhiteSpace(workingCopyPath) && Directory.Exists(workingCopyPath))
            {
                SqliteConnection.ClearAllPools();
                Directory.Delete(workingCopyPath, true);
            }
        }        
        
        public void ExtractFile(string path, string outputFileName)
        {
            EnsureInitialized();
            var file = manifestRepository.GetFile(path);
            ExtractAndDecryptFile(file, outputFileName);
        }

        public void ExtractManifestFileInfoToJson(string outputFileName)
        {
            EnsureInitialized();
            var files = manifestRepository.GetAllFiles().ToArray();
            File.WriteAllText(outputFileName, JsonConvert.SerializeObject(files, Formatting.Indented));
        }

        private void ExtractAndDecryptFile(DBFile file, string outputFilename)
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
                return; //This file is not encrypted; either a directory or empty.
            }

            var keyId = (UID) fileData["EncryptionKey"];

            var encryptionKeyArray = (NSDictionary) objects[(int) keyId.ToUInt64()];

            var encryptionKeyData = (NSData) encryptionKeyArray["NS.data"];

            var encryptionKey = encryptionKeyData.Bytes.Skip(4).ToArray();

            var innerKey = keybag.UnwrapKeyForClass(protectionClass.ToInt(), encryptionKey);

            var fileNameInBackup = Path.Combine(sourceBackupPath, file.fileID[new Range(0, 2)], file.fileID);
            
            aesEncryptionProvider.DecryptAes(fileNameInBackup, innerKey, CipherMode.CBC, outputFilename);
        }

        private string GetTemporaryDirectory()
        {
            string tempFolder = Path.GetTempFileName();
            File.Delete(tempFolder);
            Directory.CreateDirectory(tempFolder);

            return tempFolder;
        }

        private void EnsureInitialized()
        {
            if (!initialized)
            {
                PerformInitialize();
                initialized = true;
            }
        }

        private void PerformInitialize()
        {
            if (initialized)
            {
                throw new InvalidOperationException($"Already initialized. Call {nameof(EnsureInitialized)} instead of {nameof(PerformInitialize)}");
            }
            
            FileInfo file = new FileInfo(ManifestFile);
            NSDictionary rootDict = (NSDictionary)PropertyListParser.Parse(file);

            NSData backupKeyBag = (NSData)rootDict.ObjectForKey("BackupKeyBag");
            keybag = new KeyBag(backupKeyBag);

            NSData manifestKeyObject = (NSData)rootDict.ObjectForKey("ManifestKey");

            if (manifestKeyObject == null)
            {
                throw new Exception("Could not find ManifestKey. Is this an encrypted backup?");
            }

            var manifestKey = manifestKeyObject.Bytes.Skip(4).ToArray();
            var manifestClass = BitConverter.ToInt32(manifestKeyObject.Bytes.Take(4).ToArray());

            keybag.UnlockWithPassphrase(sourceBackupPassword);
            
            var key = keybag.UnwrapKeyForClass(manifestClass, manifestKey);
            
            aesEncryptionProvider.DecryptAes(ManifestDb, key, CipherMode.CBC, Path.Combine(workingCopyPath, "Manifest.db"));

            if (!manifestRepository.OpenTempDb())
            {
                throw new Exception("Manifest.db file does not seem to be the right format!");
            }
        }        
    }
}
