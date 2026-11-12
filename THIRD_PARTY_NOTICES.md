# Third-party notices

[日本語](THIRD_PARTY_NOTICES.ja.md)

SKATER+ includes or links the following third-party material:

- **Mbed TLS 2.28.8** — used by the certificate-verification bridge under
  Apache-2.0. Also used by the patcher's SD certificate importer through
  devkitPro's `3ds-mbedtls`. The complete license text is in `vendor/mbedtls/LICENSE`.
- **micro-ecc** by Kenneth MacKay — used by the ECDHE payload under the
  BSD 2-Clause license. The complete license text is in
  `vendor/micro-ecc/LICENSE.txt`.
- **OpenSSL ARM AES/GHASH** by Andy Polyakov and the OpenSSL Project — the
  upstream source subset and complete license are in `vendor/openssl-arm/`.
  The license is also embedded in the CIA/3DSX RomFS. This is arithmetic
  acceleration, not an OpenSSL library upgrade.
- **Mozilla CA Certificate Program data** — the CA snapshot is distributed
  under MPL 2.0. Its provenance is documented in
  `vendor/root-certificates/README.md`.
- **Sectigo Public Server Authentication Root E46** — a public root
  certificate obtained from Sectigo; its source URL is recorded in the
  generated certificate bundle.

The patch also interoperates with Luma3DS and Nintendo 3DS system
software. Those projects are not included as source dependencies and do not
endorse SKATER+. Nintendo stock files are not included in this repository.

- **curl 8.4.0** and **zlib 1.3.1** — used by the HTTPS updater through devkitPro portlibs. Their license texts are embedded under `patcher/romfs/licenses/`. The updater uses the pinned Mozilla CA snapshot for certificate verification.
