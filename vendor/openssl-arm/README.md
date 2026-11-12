# OpenSSL ARM arithmetic subset

Unmodified files from [openssl/openssl](https://github.com/openssl/openssl/tree/12ad22dd16ffe47f8cde3cddb84a160e8cdb3e30),
commit `12ad22dd16ffe47f8cde3cddb84a160e8cdb3e30` (1.0.2 branch).

- `aes-armv4.pl`: `crypto/aes/asm/aes-armv4.pl`
- `ghash-armv4.pl`: `crypto/modes/asm/ghash-armv4.pl`
- `arm_arch.h`: `crypto/arm_arch.h`
- `LICENSE`: complete upstream license

Only ARMv6 integer code is built. This is not an OpenSSL library upgrade.
The license is also embedded in the patcher's RomFS.
