using System;
using System.IO;
using System.Runtime.InteropServices;
using iOS.Backup.Decrypt.Library;

namespace iOS.Backup.Decrypt.Console
{
    // Currently this is just a test harness to verify it works overall by extracting a single file.
    internal static class Program
    {
        static int Main(string[] args)
        {
            //TODO: Create a more functional CLI once the rest of the code is cleaned up.
            if (!ValidateParams(args))
            {
                PrintUsage();
                return 1;
            }

            try
            {
                using var client = new iOSBackupClient(args[0], args[1]);
                //TODO: Make this a CLI option
                var manifestJsonFilename = Path.Combine(Path.GetDirectoryName(args[3]), "manifest.json");
                if (!File.Exists(manifestJsonFilename))
                {
                    client.ExtractManifestFileInfoToJson(manifestJsonFilename);
                }

                client.ExtractFile(args[2], args[3]);
                return 0;
            }
            catch (Exception ex)
            {
                System.Console.Error.WriteLine(ex.ToString());
                return 2;
            }
        }

        static bool ValidateParams(string[] args)
        {
            if (args.Length != 4)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(args[0]) || !Directory.Exists(args[0]))
            {
                System.Console.Error.WriteLine("The source backup path does not exist.");
                return false;
            }
            
            // Can't completely validate this arg, since we need to attempt decryption to know the password is right.
            if (string.IsNullOrWhiteSpace(args[1]))
            {
                System.Console.Error.WriteLine("The password is required, and cannot be blank.");
                return false;
            }
            
            // Can't completely validate this arg, since we need to decrypt the manifest first.
            if (string.IsNullOrWhiteSpace(args[2]))
            {
                System.Console.Error.WriteLine("The relative filename to extract is required, and cannot be blank.");
                return false;
            }
            
            if (string.IsNullOrWhiteSpace(args[3]) || !Directory.Exists(Path.GetDirectoryName(args[3])))
            {
                System.Console.Error.WriteLine("The output filename directory must already exist.");
                return false;
            }
            
            if (File.Exists(args[3]))
            {
                System.Console.Error.WriteLine("The output filename already exists.");
                return false;
            }

            return true;
        }

        static void PrintUsage()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                System.Console.WriteLine(
                    $"Usage: iOS.Backup.Decrypt.Console.exe [BACKUP_PATH] [PASSWORD] [RELATIVE_SOURCE_FILENAME] [OUTPUT_FILENAME]");
            }
            else
            {
                System.Console.WriteLine(
                    $"Usage: ./iOS.Backup.Decrypt.Console [BACKUP_PATH] [PASSWORD] [RELATIVE_SOURCE_FILENAME] [OUTPUT_FILENAME]");
            }
        }
    }
}
