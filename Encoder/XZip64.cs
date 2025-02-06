﻿using System;
using System.IO;
using System.IO.Compression;

namespace Encoder
{
    /// <summary>
    /// Provides compression and encryption functionality for binary data
    /// </summary> 
    class XZip64
    {
        public static string Encode(byte[] payload, string key)
        {
            if (payload == null || payload.Length == 0) throw new ArgumentNullException("payload");
            if (string.IsNullOrEmpty(key)) throw new ArgumentNullException("key");

            string encoded = null;
            using (var input = new MemoryStream(Shuffle(payload, key)))
            using (var output = new MemoryStream())
            using (var gzip = new GZipStream(output, CompressionMode.Compress))
            {
                try {
                    byte[] buffer = new byte[4096];
                    int bytes;
                    while ((bytes = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        gzip.Write(buffer, 0, bytes);
                    }
                    gzip.Close();
                    encoded = Convert.ToBase64String(output.ToArray());
                    Array.Clear(buffer, 0, buffer.Length);
                }
                catch (Exception ex) {
                    throw new Exception("Failed to encode data", ex);
                }
            }
            return encoded;
        }

        public static byte[] Decode(string encoded, string key)
        {
            byte[] decoded = null, buffer = new byte[4096]; int bytes = 0; MemoryStream input = new MemoryStream(Convert.FromBase64String(encoded)), output = new MemoryStream(); GZipStream gzip = new GZipStream(input, CompressionMode.Decompress);
            try
            {
                while ((bytes = gzip.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, bytes);
                }
                decoded = Shuffle(output.ToArray(), key);
            }
            catch (Exception) { }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
                input.Position = 0; input.SetLength(0); input.Close(); input.Dispose();
                output.Position = 0; output.SetLength(0); output.Close(); output.Dispose();
                gzip.Close(); gzip.Dispose();
            }
            return decoded;
        }

        private static byte[] Shuffle(byte[] payload, string key)
        {
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)(payload[i] ^ key[i % key.Length]);
            }
            return payload;
        }
    }
}


