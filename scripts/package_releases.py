#!/usr/bin/env python3
"""Create locally generated Luma installation archives."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import zipfile
from pathlib import Path

from build_regional_tls_packages import REGIONS, ROOT
from verify_regional_tls_build import EXPECTED_IPS
from build_update_manifest import write_manifest


CRO = ROOT / "build" / "oss-skaterplus.cro.lex"
CRR = ROOT / "build" / "tlsfix.crr"
ROOTCA = ROOT / "build" / "rootca.pem"
PROJECT_LICENSE = ROOT / "LICENSE"
THIRD_PARTY_NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"
THIRD_PARTY_NOTICES_JA = ROOT / "THIRD_PARTY_NOTICES.ja.md"
MBEDTLS_LICENSE = ROOT / "vendor" / "mbedtls" / "LICENSE"
MICRO_ECC_LICENSE = ROOT / "vendor" / "micro-ecc" / "LICENSE.txt"
OPENSSL_LICENSE = ROOT / "vendor" / "openssl-arm" / "LICENSE"
DIST = ROOT / "dist"
PATCHER_OUTPUTS = (
    ROOT / "patcher" / "skater-plus-patcher.3dsx",
    ROOT / "patcher" / "skater-plus-patcher.cia",
)
CRO_SHA256 = "0DA1A8231272D7A7F09AD504D8701B7929AA5A4B1C1391500C36D46AC1351B47"
CRR_SHA256 = "86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422"
ROOTCA_SHA256 = "35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0"
ZIP_TIME = (2026, 10, 23, 0, 0, 0)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def checked(path: Path, expected: str) -> bytes:
    data = path.read_bytes()
    actual = sha256(data)
    if actual != expected:
        raise RuntimeError(f"{path}: SHA-256 {actual}; expected {expected}")
    return data


def check_cia_version(path: Path) -> None:
    """Check the actual ticket/TMD, not just build command arguments."""
    data = path.read_bytes()
    header, cert, ticket = struct.unpack_from('<I', data)[0], *struct.unpack_from('<II', data, 8)
    align = lambda size: (size + 63) & ~63
    ticket_offset = align(header) + align(cert)
    tmd_offset = ticket_offset + align(ticket)
    signature_sizes = {0x10000: 0x240, 0x10001: 0x140, 0x10002: 0x80,
                       0x10003: 0x240, 0x10004: 0x140, 0x10005: 0x80}
    versions = []
    for offset, field in ((ticket_offset, 0xA6), (tmd_offset, 0x9C)):
        signature = struct.unpack_from('>I', data, offset)[0]
        versions.append(struct.unpack_from('>H', data, offset + signature_sizes[signature] + field)[0])
    makefile = (ROOT / 'patcher/Makefile').read_text(encoding='utf-8')
    expected = int(re.search(r'^APP_TITLE_VERSION\s*:=\s*(\d+)', makefile, re.M)[1])
    if versions != [expected, expected]:
        raise RuntimeError(f'CIA ticket/TMD versions {versions}; expected {expected}. Check makerom version handling.')
    print(f'PASS CIA title version {expected >> 10}.{(expected >> 4) & 63}.{expected & 15} (v{expected})')


def add_file(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--include-local-full-files", action="store_true",
        help="also make local-only ZIPs containing complete reconstructed files",
    )
    args = parser.parse_args()
    DIST.mkdir(parents=True, exist_ok=True)
    for stale in DIST.glob("SKATER-plus-*.zip"):
        stale.unlink()
    if args.include_local_full_files:
        cro = checked(CRO, CRO_SHA256)
        crr = checked(CRR, CRR_SHA256)
        rootca = checked(ROOTCA, ROOTCA_SHA256)
        legal_files = {
            "SKATER-plus/LICENSE.txt": PROJECT_LICENSE.read_bytes(),
            "SKATER-plus/THIRD_PARTY_NOTICES.md": THIRD_PARTY_NOTICES.read_bytes(),
            "SKATER-plus/THIRD_PARTY_NOTICES.ja.md": THIRD_PARTY_NOTICES_JA.read_bytes(),
            "SKATER-plus/LICENSES/Mbed-TLS.txt": MBEDTLS_LICENSE.read_bytes(),
            "SKATER-plus/LICENSES/micro-ecc.txt": MICRO_ECC_LICENSE.read_bytes(),
            "SKATER-plus/LICENSES/OpenSSL.txt": OPENSSL_LICENSE.read_bytes(),
        }
        for region, metadata in REGIONS.items():
            ips = checked(ROOT / "patches" / region / "code.ips", EXPECTED_IPS[region])
            title = metadata["luma_title"]
            prefix = f"luma/titles/{title}"
            output = DIST / f"SKATER-plus-{region}.zip"
            with zipfile.ZipFile(output, "w") as archive:
                add_file(archive, f"{prefix}/code.ips", ips)
                add_file(archive, f"{prefix}/romfs/os2.cro.lex", cro)
                add_file(archive, f"{prefix}/romfs/.crr/tlsfix.crr", crr)
                add_file(archive, f"{prefix}/romfs/browser/rootca.pem", rootca)
                for name, data in legal_files.items():
                    add_file(archive, name, data)
            digest = sha256(output.read_bytes())
            print(f"PASS local-only {region} {output.name} sha256={digest}")
    for source in PATCHER_OUTPUTS:
        if not source.is_file():
            raise RuntimeError(f"missing patcher build: {source}")
        if source.suffix == '.cia':
            check_cia_version(source)
        output = DIST / source.name
        shutil.copyfile(source, output)
        digest = sha256(output.read_bytes())
        print(f"PASS patcher {output.name} sha256={digest}")
    print(f"PASS updater metadata {write_manifest(DIST).name}")


if __name__ == "__main__":
    main()
