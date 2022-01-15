## CUBDROP Usage

To create CUBDROP-ready embedded resources you need to use FILEGUARD 

1. Run `Fileguard.exe <file>` to generated a CUBDROP-ready resource file
2. Add the created `.enc` files to your CUBDROP Visual Studio project and switch the `Build Action` state to `Embedded Resource`
3. Compile and run CUBDROP

CUBDROP is a dropper and DLL-sideloading utility that on execution executes WARFOX DLL payloads, CUBDROP performs the following

1. On execution CUBDROP checks if the `C:\Users\Public\Windows Defender` directory exists, if it doesn't it's created via a call to `CreateDirectory`
2. Two embedded resources are located by their hardcoded name, `payload_dll.enc` is the embedded WARFOX DLL payload, and `loader_exe.enc` is the legitimate program used to DLL-sideload WARFOX. By default, WARFOX is executed via `MspEng.exe` via its `ServiceCtrMain` export
3. The AES keys used to decrypt the resources are retrieved from the end of the resource file
4. Both resources are decrypted via AES-128 in CBC mode using the extracted key
5. Both resources are decompressed via GZIP
6. Both resources are written to the `Windows Defender` directory created in the Public users directory
7. The legitimate `MspEng.exe` executable is executed which results in `MpSvc.dll` (WARFOX DLL payload) being sideloaded

## Notes

- CUBDROP was originally written in C++, but using Boost GZIP was a problem due to ZLIB version compatibility issues, additionally, statically included a header-only version of ZLIB inflated the compiled CUBDROP binary over 150KB which was an issue
- Porting CUBDROP back to C++ can and should be done since C# isn't the best option (being an interpreted language)
- The current version of CUBDROP doesn't include any string or function call obfuscation, using a free C# obfuscator such as ConfuserEx may be useful but irresponsible
- This copy of CUBDROP source code includes debug output/statements which would need to be removed 

## Caveats

- Currently the AES IV is hardcoded by both FILEGUARD and CUBDROP, an alternative would be to randomly generate an IV and appended alongside with the AES key
