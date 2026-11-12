# SKATER+

[日本語](README.ja.md)

SKATER+ adds TLS 1.2, root certificates, and website compatibility fixes to the New Nintendo 3DS Internet Browser. Luma3DS loads the patch from the SD card when the browser starts.

> [!CAUTION]
> **Most of the code and documentation were created with generative AI assistance.**

## Download

- [CIA](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia)
- [3DSX](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.3dsx)

<a href="https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia"><img src="docs/images/cia-qr.png" alt="" width="240" height="240"></a>

## Features

- TLS 1.2 with ECDHE-RSA/ECDHE-ECDSA AES-GCM.
- P-256/P-384 certificate and handshake-signature verification.
- [26 additional root certificates](docs/CERTIFICATES.md).
- Import your own root certificates from SD with the patcher.
- iOS 7-era mobile Safari user agent and HTTPS Google search.
- Japanese first-run setup fix, confirmed on hardware with unmodified save data.

Google treats the stock iOS 6 user agent as unsupported. Search was confirmed while signed in with the patched iOS 7-era user agent.

## How it works

`code.ips` changes the browser's crypto module filename, user agent, Google search URL, and Japanese first-run registration. Luma3DS loads the patched OpenSSL module `os2.cro.lex` and its module identity file, `tlsfix.crr`.

The browser's OpenSSL 1.0.2 module handles TLS. Mbed TLS supplies P-256/P-384 public-key parsing and ECDSA signature verification. The added certificate authorities are stored in `rootca.pem`.

Japanese first-run registration connects to `sec.ifilter.jp` over HTTP. Use a trusted network for setup because the device identifier and response are sent unencrypted.

## Compatibility

| Region | Luma title folder | Status |
| --- | --- | --- |
| JPN | `0004003000008802` | Real hardware: first-run, Wikipedia, Google, Yahoo, certificates and mobile UA confirmed |
| USA | `0004003000009402` | Community hardware report: region detection, install, Wikipedia and Yahoo.com work (v0.1.0) |
| KOR | `000400300000AE02` | Launch/UA confirmed in Azahar; TLS needs real hardware |
| EUR/AUS | `0004003000009D02` | EUR community hardware report: region detection, install, Wikipedia and Yahoo work (v0.1.0) |

USA/EUR results are [community reports](https://www.reddit.com/r/3dshomebrew/comments/1xhlyu2/). The TLS optimizations were tested on JPN hardware; USA/EUR retesting is pending.

China/Taiwan and Old Nintendo 3DS SPIDER are outside this project's scope.
See [regional compatibility](docs/COMPATIBILITY.md).

## Install

Requirements: a New Nintendo 3DS-family system, the latest regional browser
update, and an up-to-date Luma3DS release.

1. Boot while holding <kbd>Select</kbd>, enable **Enable game patching**, and
   save with <kbd>Start</kbd>. The patcher also checks this setting at startup.
2. Install the CIA and launch **SKATER+ Patcher** from HOME Menu, or open the 3DSX from Homebrew Launcher.
3. Press <kbd>A</kbd>. The patcher detects JPN, USA, EUR/AUS, or KOR, reads
   the official browser files, verifies them, and builds the Luma patch on SD.
4. CIA users can choose whether to keep or uninstall the patcher. Exit normally
   when using the 3DSX build.
5. Launch the browser and test the sites you want to use.

Launch the patcher again and press <kbd>Y</kbd>, then <kbd>A</kbd> to confirm to delete SKATER+ files.
A reboot is not required after removal. If matching paths already contain
other files, the patcher keeps backup copies but does not restore them
automatically.

Press <kbd>X</kbd> to uninstall the patcher CIA at any time, including before
installing the patch and from an error screen.

To add a root certificate, place one PEM certificate per `.pem` or `.crt` file
in `sd:/3ds/skater-plus-patcher/certs/`. Launch the patcher with the patch
installed, press <kbd>L</kbd>, and confirm each root's subject and SHA-256
fingerprint. See [Certificates](docs/CERTIFICATES.md#adding-your-own-roots).
Press <kbd>R</kbd> to select and remove an imported root certificate.

## Updates

At startup the patcher checks the latest stable tag with one HTTPS HEAD request.
It does not download release metadata unless you accept a newer version.
Press <kbd>Select</kbd> to check again.
An unavailable network does not prevent normal patch installation.

After updating, exit and reopen the patcher. If an older browser patch is
installed, press <kbd>A</kbd> to update it directly. Registered extra certificates
are preserved, and recognized older layouts are migrated automatically.
CIA updates replace the installed patcher; 3DSX updates replace its HBL launch
path after download verification. The first upgrade from v0.1.0 must be installed manually.

On JPN hardware, the startup update check took 1.62 seconds. Applying the patch with SD writes took 5.19 seconds, and reapplying an unchanged patch took 2.42 seconds.

## TLS performance

### Certificate verification

TLS connection setup was measured on a Japanese New 3DS using a local server. Measurements that reused a TLS session were excluded.

| Issuer key / connection authentication | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| P-256 / RSA | 916 ms | 402 ms | 56.0% |
| P-256 / ECDSA | 1,311 ms | 312 ms | 76.2% |
| P-384 / RSA | 1,558 ms | 320 ms | 79.4% |
| P-384 / ECDSA | 2,174 ms | 427 ms | 80.4% |

### AES-GCM

On the same console, the 1 MiB transfer was timed from the first receive progress notification to completion. The table shows the median for each condition.

| Connection authentication / cipher | Before | After | Reduction |
| --- | ---: | ---: | ---: |
| RSA / AES-128-GCM | 573 ms | 454.5 ms | 20.7% |
| RSA / AES-256-GCM | 637 ms | 482 ms | 24.3% |
| ECDSA / AES-128-GCM | 602 ms | 486 ms | 19.3% |
| ECDSA / AES-256-GCM | 603 ms | 523.5 ms | 13.2% |

## Screenshots

| Wikipedia | Google | Yahoo.com |
| --- | --- | --- |
| ![Wikipedia over HTTPS](docs/images/wikipedia.png) | ![Google search](docs/images/google.png) | ![Yahoo.com](docs/images/yahoo-com.png) |

## Building

Building the patcher uses the included runtime assets. Regenerating the browser
patches requires personally dumped browser files. See the [build guide](docs/BUILDING.md).

## Reporting issues

Site compatibility depends on the browser's JavaScript, HTML/CSS, codecs, and TLS support.

Include your console model and region, system and Luma3DS versions, browser title ID, URL, error code, and the result before applying the patch.

## Credits and license

Thanks to Luma3DS, OpenSSL, Mbed TLS, micro-ecc, and the 3DS reverse-engineering
community. Original code is MIT licensed. Third-party terms are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
