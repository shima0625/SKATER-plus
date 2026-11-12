# Building SKATER+

[日本語](BUILDING.ja.md)

## Build the patcher

The committed runtime assets are ready to use. With devkitARM, libctru, and
makerom and the devkitPro `3ds-mbedtls`, `3ds-curl` and `3ds-zlib` packages installed, build both
applications without extracting browser files:

```text
make -C patcher
make -C patcher cia MAKEROM=makerom
python scripts/package_releases.py
```

## Regenerate browser patches

Put the supported files extracted from your own system in `input/`:

| File | SHA-256 |
| --- | --- |
| `JPN.code.bin` | `8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914` |
| `USA.code.bin` | `B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C` |
| `KOR.code.bin` | `7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4` |
| `EUR.code.bin` | `748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28` |
| `oss.cro` | `BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE` |

Also provide the matching 0x1000-byte `static.crr`. Rebuilding the root bundle
requires the supported stock `rootca.pem`.

Run from the repository root:

```powershell
python scripts/build_regional_tls_packages.py --input-dir input
python scripts/verify_regional_tls_build.py --input-dir input
python scripts/build_ecdhe_static_patch.py
sh scripts/build_certificate_objects.sh /path/to/mbedtls-2.28.8
python scripts/build_certificate_bridge.py
sh scripts/build_ecdh_objects.sh
python scripts/build_ecdh_acceleration.py
sh scripts/build_aes_objects.sh
python scripts/build_aes_acceleration.py
python scripts/build_matching_crr.py
pwsh -File scripts/build_rootca_bundle.ps1 -StockPath input/rootca.pem -OutputPath build/rootca.pem
python scripts/build_runtime_assets.py
```

`package_releases.py` packages the patcher CIA and 3DSX.

Root-bundle rebuild alone:

```powershell
pwsh -File scripts/build_rootca_bundle.ps1 -StockPath input/rootca.pem -OutputPath build/rootca.pem
```

Important final hashes:

| Output | SHA-256 |
| --- | --- |
| `build/oss-skaterplus.cro.lex` | `0DA1A8231272D7A7F09AD504D8701B7929AA5A4B1C1391500C36D46AC1351B47` |
| `build/tlsfix.crr` | `86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422` |
| `build/rootca.pem` | `35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0` |

The scripts stop on an unsupported input, changed patch site, or mismatched
output.

`build_runtime_assets.py` updates the deltas under `patcher/romfs/assets/`.
After regenerating them, rebuild the patcher using the commands above.

The certificate-object build uses devkitARM GCC 16.1.0 and Mbed TLS 2.28.8
sources. Run the `sh` command in the same Linux/devkitPro environment as the
patcher build. Test the integrated CRO with `python scripts/emulate_certificate_bridge.py`
(requires Unicorn 2.1.4 and cryptography 48.0.1). CI uses `--elf-only` so it
does not require browser dumps. Output CIA/3DSX files are local test builds;
this build process does not upload or publish them.

The updater uses curl 8.4+ with Mbed TLS. The committed updater CA bundle contains eight roots selected from the pinned Mozilla snapshot; regenerate it with `python scripts/build_updater_ca.py`. `package_releases.py` generates CIA/3DSX files and `update.txt`, which binds their sizes and SHA-256 digests to the version. Attach all three to the same release tag.

The packager checks the actual CIA ticket and TMD versions. Older Project_CTR makerom builds have a `VER_MAJOR`/`VER_MINOR` name collision: apply `scripts/makerom-version.patch` in the makerom source directory and rebuild the tool if this check fails. A failed version check must not be bypassed.
