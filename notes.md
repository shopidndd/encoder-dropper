**Using the Dropper**

The Dropper project loads an encoded payload from an embedded resource and decodes it at runtime.

## Configuration

Encoded Payload:
Ensure the file EncodedPayload.txt (which contains your full encoded payload) is added to the Dropper project.
Set its Build Action to Embedded Resource (in the file properties).
Decoding Key:
In Program.cs, replace "YOUR_DECODING_KEY_HERE" with the key used during encoding.

## Target Process:
The example uses an encoded version of "cmd.exe" to form the target process path. You can modify this as needed.
Running the Dropper
When you run Dropper.exe, it will:
Load the encoded payload from EncodedPayload.txt.
Decode it using the provided key.
Decode an encoded target process name (e.g., "cmd.exe") and build the full path.
Call the process hollowing routine to (in this demo) simply launch the target process.

## Note:
The process hollowing implementation in this demo is a placeholder that simply launches the target process. In a production dropper, you would implement full process hollowing to inject the payload into a suspended process.