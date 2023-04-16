using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Claunia.PropertyList;

namespace iOS.Backup.Decrypt.Library
{
    public class KeyBag
    {
        private const int WrapPassphrase = 2;

        private readonly AesEncryptionProvider aesEncryptionProvider;
        private readonly string[] tags = { nameof(ClassKey.WRAP), nameof(ClassKey.CLAS), nameof(ClassKey.KTYP), nameof(ClassKey.WPKY) };
        private readonly Dictionary<string, byte[]> attribs = new Dictionary<string, byte[]>();
        private readonly Dictionary<int, ClassKey> classKeys = new Dictionary<int, ClassKey>();        
        
        private int? Type { get; set; }
        private int? Wrap { get; set; }
        private byte[] UUID { get; set; }

        public KeyBag(NSData data)
        {
            aesEncryptionProvider = new AesEncryptionProvider();
            ParseKeybag(data);
        }

        public bool UnlockWithPassphrase(string passPhrase)
        {
            byte[] bytes;

            using (var deriveBytes = new Rfc2898DeriveBytes(passPhrase, attribs["DPSL"], Unpack32BitSignedInt(attribs["DPIC"]), HashAlgorithmName.SHA256))
            {
                bytes = deriveBytes.GetBytes(32);
            }

            var passphrase_round1 = bytes;

            using (var deriveBytes = new Rfc2898DeriveBytes(passphrase_round1, attribs["SALT"], Unpack32BitSignedInt(attribs["ITER"]), HashAlgorithmName.SHA1))
            {
                bytes = deriveBytes.GetBytes(32);
            }

            var passphrase_key = bytes;

            foreach (var classKey in classKeys)
            {
                if (classKey.Value.WPKY == null)
                {
                    continue;
                }

                if (classKey.Value.WRAP == WrapPassphrase)
                {
                    var k = AESUnwrap(passphrase_key, classKey.Value.WPKY);

                    if (k == null)
                    {
                        return false;
                    }

                    classKey.Value.Key = k;
                }
            }

            return true;
        }
        
        public byte[] UnwrapKeyForClass(int manifestClass, byte[] manifestKey)
        {
            var ck = classKeys[manifestClass].Key;

            if (ck == null)
            {
                throw new Exception("Key not found, did you provide the correct pass phrase?");
            }

            if (manifestKey.Length != 0x28)
            {
                throw new Exception("Invalid key length");
            }

            return AESUnwrap(ck, manifestKey);
        }        

        private byte[] AESUnwrap(byte[] kek, byte[] wrapped)
        {
            var C = new List<ulong>();
            var test = Enumerable.Range(0, wrapped.Length / 8);

            foreach (var i in test)
            {
                C.Add(Unpack64BitUnsignedInt(wrapped[new Range(i * 8, i * 8 + 8)]));
            }

            var n = C.Count - 1;
            var r = new ulong[n + 1];
            var a = C[0];

            for (int i = 1; i < n + 1; i++)
            {
                r[i] = C[i];
            }

            foreach (int j in Enumerable.Range(0, 6).Reverse())
            {
                foreach (int i in Enumerable.Range(1, n).Reverse())
                {
                    var first = Pack64BitUnsignedInt(a ^ (ulong)(n * j + i));
                    var second = Pack64BitUnsignedInt(r[i]);

                    var todec = first.Concat(second).ToArray();

                    var b = aesEncryptionProvider.DecryptAes(todec, kek, CipherMode.ECB);

                    a = Unpack64BitUnsignedInt(b.Take(8).ToArray());
                    r[i] = Unpack64BitUnsignedInt(b.Skip(8).ToArray());
                }
            }

            if ((ulong)a != 0xa6a6a6a6a6a6a6a6)
            {
                return null;
            }

            var res = r.Skip(1).Select(Pack64BitUnsignedInt).SelectMany(m => m).ToArray();
            return res;
        }

        private void ParseKeybag(NSData nsData)
        {

            ClassKey currentClassKey = null;

            foreach (var (tag, data) in LoopTLVBlocks(nsData))
            {
                var dataAsInt = 0;

                if (data.Length == 4)
                {
                    dataAsInt = Unpack32BitSignedInt(data);
                }

                if (tag == "TYPE")
                {
                    Type = dataAsInt;
                    if (Type > 3)
                    {
                        throw new Exception($"FAIL: keybag type > 3 : {Type}");
                    }

                }
                else if (tag == "UUID" && UUID == null)
                {
                    UUID = data;
                }
                else if (tag == "WRAP" && Wrap == null)
                {
                    Wrap = dataAsInt;
                }
                else if (tag == "UUID")
                {
                    if (currentClassKey != null)
                    {
                        classKeys.Add(currentClassKey.CLAS, currentClassKey);
                    }

                    currentClassKey = new ClassKey { UUID = data };
                }
                else if (tags.Contains(tag) && currentClassKey != null)
                {
                    if (tag == nameof(ClassKey.CLAS))
                    {
                        currentClassKey.CLAS = dataAsInt;
                    }
                    else if (tag == nameof(ClassKey.KTYP))
                    {
                        currentClassKey.KTYP = dataAsInt;
                    }
                    else if (tag == nameof(ClassKey.WPKY))
                    {
                        currentClassKey.WPKY = data;
                    }
                    else if (tag == nameof(ClassKey.WRAP))
                    {
                        currentClassKey.WRAP = dataAsInt;
                    }

                }
                else
                {
                    attribs.Add(tag, data);
                }
            }

            if (currentClassKey != null)
            {
                classKeys.Add(currentClassKey.CLAS, currentClassKey);
            }
        }

        private IEnumerable<(string, byte[])> LoopTLVBlocks(NSData nsData)
        {
            var blob = nsData.Bytes;

            var i = 0;
            while (i + 8 <= blob.Length)
            {
                var tag = blob[new Range(i, i + 4)];
                var length = Unpack32BitSignedInt(blob[new Range(i + 4, i + 8)]);
                var data = blob[new Range(i + 8, i + 8 + length)];
                yield return (Encoding.ASCII.GetString(tag), data);
                i += 8 + length;
            }
        }
        
        private byte[] Pack64BitUnsignedInt(ulong l)
        {
            return BitConverter.GetBytes(l).Reverse().ToArray();
        }

        private ulong Unpack64BitUnsignedInt(byte[] bytes)
        {
            return BitConverter.ToUInt64(bytes.Reverse().ToArray());
        }
        
        private int Unpack32BitSignedInt(byte[] bytes)
        {
            return BitConverter.ToInt32(bytes.Reverse().ToArray());
        }
        
        private class ClassKey
        {
            public int CLAS { get; set; }
            public byte[] UUID { get; set; }
            public int? WRAP { get; set; }
            public int? KTYP { get; set; }
            public byte[] WPKY { get; set; }
            public byte[] Key { get; set; }
        }        
    }
}
