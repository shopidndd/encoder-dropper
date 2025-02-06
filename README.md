# Dropper & Encoder Project

> **DISCLAIMER:**  
> This project is provided for educational and authorized penetration testing purposes only. The techniques implemented herein (such as process hollowing and payload injection) may be illegal or unethical if used without explicit permission. Use this project only in controlled and authorized environments.

## Overview

This solution contains two projects:

1. **Encoder**  
   A command-line tool that reads an input file (e.g., an EXE), compresses it with GZip, applies an XOR obfuscation using a user-specified key, and then Base64‑encodes the result. The output is written to a file with a `.zip64.txt` extension. This encoded payload can later be used by the Dropper project.

2. **Dropper**  
   A dropper application that loads an encoded payload from an embedded resource (EncodedPayload.txt), decodes it using the same key, and then (in a real-world scenario) injects the payload into a target process via process hollowing. In this example, the process hollowing routine simply launches a target process (e.g., `cmd.exe`).

## File Structure



## Prerequisites

- **Visual Studio 2017/2022** (or later)  
- **.NET Framework 3.5** (or later, depending on your target settings)
- Basic knowledge of C# and building projects in Visual Studio

## Building the Projects

1. **Open the Solution:**  
   Open `dropper.sln` in Visual Studio.

2. **Build the Encoder Project:**  
   - Right-click the **Encoder** project in Solution Explorer and select **Build**.  
   - The Encoder tool will compile to an executable (e.g., `bin\Debug\Encoder.exe`).

3. **Build the Dropper Project:**  
   - Right-click the **Dropper** project and select **Build**.  
   - The Dropper tool will compile to an executable (e.g., `bin\Debug\Dropper.exe`).

## Using the Encoder

The Encoder project is a command-line tool used to generate an encoded payload from a target file.

### Command-Line Usage

```shell
Encoder.exe <file> <key>

Encoder.exe "C:\Path\To\YourInputFile.exe" "MySecretKey123"

