﻿using System;
using System.IO;

namespace Encoder
{
    class Program
    {
        static void Main(string[] args)
        {
            string file = "", key = "";
            if (args.Length != 2 || (file = args[0].Trim()).Length < 1 || (key = args[1].Trim()).Length < 1)
            {
                Console.WriteLine("Usage: Encoder.exe <file> <key>");
            }
            else if (!File.Exists(file))
            {
                Console.WriteLine(string.Format("'{0}' does not exists.", Path.GetFullPath(file)));
            }
            else
            {
                string output = Path.ChangeExtension(file, ".zip64.txt");
                File.WriteAllText(output, XZip64.Encode(File.ReadAllBytes(file), key));
                Console.WriteLine(string.Format("Compressed and encoded payload has been saved to '{0}'.", Path.GetFullPath(output)));
                File.WriteAllBytes("decoded.txt", XZip64.Decode(File.ReadAllText(output), key));
            }
        }
    }
}
