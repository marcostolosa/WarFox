## Change Log

## WarFox v1.1 (January 13, 2022)

**New Features**

- WARFOX proxies it's network communications through another process via named pipes (see the "Transport Proxy" documentation)
- Added "CUBDROP", a C# payload dropper and DLL side-sideloading utility that executes payloads created by FILEGUARD
- Added the ability to generated new self-signed certificates with the usage of `!generate_cert`

**Improvements**

- Added a layer of AES-128 CBC encryption to network traffic for WARFOX to ensure the traffic remains encrypted if a TLS MITM attack occurs
    - ! WARNING ! -- Currently the key is hardcoded and it's expected to be pre-shared with the server
- HIGHTOWER can now handle additional HTTP methods such as HEAD and PUT
- Added additional error-checking to make HIGHTOWER more user-friendly
- The build_config.py script now generates an RSA public/private key pair
