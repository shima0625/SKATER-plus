# SKATER+ Patcher

Nintendo 3DS frontend for generating and removing the SKATER+ Luma patch. It
reads and verifies the installed browser, applies redistributable deltas, and
writes the patch to the SD card.
It uses Luma3DS's service-control extension plus the system Loader/FS services
to read the installed browser RomFS; no browser file or title key is bundled.

Supported regions: JPN, USA, EUR/AUS, and KOR. CN/TWN are excluded because
SKATER is a New Nintendo 3DS browser and those regions only shipped Old 3DS.
Both the CIA and 3DSX builds are supported. At startup the patcher checks
Luma3DS's **Enable game patching** setting and displays the required boot-menu
steps if it is disabled.

The CIA optionally removes itself after a successful install. Reinstall it to
remove the patch later. Pre-existing files at managed paths are backed up under
`sdmc:/3ds/skater-plus-patcher/`, but are not restored automatically.

Press **L** when the patch is installed to import self-signed PEM CA roots from
`sdmc:/3ds/skater-plus-patcher/certs/`. See [Certificates](../docs/CERTIFICATES.md).

Build with devkitARM/libctru, devkitPro's `3ds-mbedtls`, `3ds-curl`, and `3ds-zlib`, and the included runtime assets:

```text
make -C patcher
make -C patcher cia MAKEROM=makerom
```

CIA packaging requires `makerom`. To regenerate the included banner, use
`bannertool`:

```text
bannertool makebanner -i patcher/assets/banner.png \
  -a patcher/assets/silent.wav -o patcher/assets/banner.bin
```
