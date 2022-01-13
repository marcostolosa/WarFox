- [ ] Relying on ZLIB causes it to statically link the required library which inflates the binary by 100+ KB, static linking is necessary but an alternative compression algorithm might be better (MSZIP or something that be decompressed via WinAPI)

- [ ] The AES key used to encrypt network traffic is hardcoded and needs to be pre-shared
	- [ ] Fix: Apply a secure key sharing mechanism via RSA+AES
- [ ] The AES key used for decrypt the embedded configuration data is hardcoded
	- [ ] Fix: Derive the key from the MD5 hash of an obfuscated string
- [ ] HIGHTOWER doesn't properly handle multiple sessions
	- [ ] Add a DB to maintain a history of unique inbound beacon requests, develop a "per-session" task issuing mechanism
