#!/usr/bin/env python3
"""Verify committed payloads and regional IPS files without private inputs."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from build_regional_tls_packages import REGIONS, ROOT, patch_code


EXPECTED_IPS = {
    "JPN": "48B5FA570386DCA966C8FFE70854F23B9C8CEB45FCCD3FDE63F4186CE18BB859",
    "USA": "D7AAB13E2A3608E9662B668E2628AC2E45DA5DDFF7A0495230449B7A5A1A40E8",
    "KOR": "786805C05FE3DBA35096FBB385E0FC45F415B319304E3BB8A79C0B5033EBDF68",
    "EUR": "D7AAB13E2A3608E9662B668E2628AC2E45DA5DDFF7A0495230449B7A5A1A40E8",
}

EXPECTED_PAYLOADS = {
    "aes-gcm-arm.elf": "C5A7344302711C63EF2E97F707FF64D8E650F962472D799936F1F484C934A81E",
    "ecdh-arm.elf": "43249E4CB44F046DAE67B2E9BCD6F2D5BF5D6946FD15672DCB13C6F79EE66629",
    "cipher_lookup_linear.bin": "F85461D8A8A299D2137645750C0369A3C8373829B1ED192FFCAF636E80C33379",
    "clienthello_hook.bin": "E658E420D40FA3DEDA8960E8DEABCB9F4F01AE89808FD3869B699C10E78F0DDA",
    "payload-rsa-ecdsa.bin": "FEBEF0050C39711FAE40EE447F7B16BDD4B2168CEC908D0596F463EBFE7FEFB9",
    "certificate-bridge/ec_bridge.elf": "0A089C9275394D81BC62661951560ADE9EEB368E6973AAE7CFBD5DAA560492C1",
}

EXPECTED_PATCHER_HASHES = {
    "source_raw_sha": "BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE",
    "target_raw_sha": "EA80E68D35A669D3BC44FEE6F88D4A1CB9C55248AA81C2B1D1125D8A1FA17B4A",
    "stock_root_sha": "3D7E053FB7B8AD425AB7C0AE4523B837163CA9D436F8BFE43C8FE730636D04E2",
    "target_root_sha": "35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0",
    "target_crr_sha": "86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def apply_ips(source: bytes, patch: bytes) -> bytes:
    if not patch.startswith(b"PATCH"):
        raise ValueError("bad IPS header")
    out = bytearray(source)
    cursor = 5
    while patch[cursor:cursor + 3] != b"EOF":
        if cursor + 5 > len(patch):
            raise ValueError("truncated IPS record")
        offset = int.from_bytes(patch[cursor:cursor + 3], "big")
        size = int.from_bytes(patch[cursor + 3:cursor + 5], "big")
        cursor += 5
        if size:
            if cursor + size > len(patch):
                raise ValueError("truncated IPS payload")
            if offset + size > len(out):
                raise ValueError("IPS payload exceeds source image")
            out[offset:offset + size] = patch[cursor:cursor + size]
            cursor += size
        else:
            if cursor + 3 > len(patch):
                raise ValueError("truncated IPS RLE payload")
            count = int.from_bytes(patch[cursor:cursor + 2], "big")
            if count == 0 or offset + count > len(out):
                raise ValueError("invalid IPS RLE range")
            out[offset:offset + count] = patch[cursor + 2:cursor + 3] * count
            cursor += 3
    if cursor + 3 != len(patch):
        raise ValueError("unexpected bytes after IPS EOF")
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input-dir", type=Path,
        help="optional directory containing JPN/USA/KOR/EUR.code.bin dumps",
    )
    args = parser.parse_args()

    patcher_source = (ROOT / "patcher" / "source" / "main.c").read_text(encoding="utf-8")
    for name, expected in EXPECTED_PATCHER_HASHES.items():
        match = re.search(
            rf"static const u8 {name}\[32\]=\{{([^}}]+)\}};", patcher_source
        )
        if not match:
            raise RuntimeError(f"patcher: missing {name}")
        values = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))
        actual = values.hex().upper()
        if len(values) != 32 or actual != expected:
            raise RuntimeError(f"patcher: {name} mismatch ({actual})")
        print(f"PASS patcher/{name} {actual}")

    for name, expected in EXPECTED_PAYLOADS.items():
        actual = sha((ROOT / "payload" / name).read_bytes())
        if actual != expected:
            raise RuntimeError(f"payload/{name}: hash mismatch")
        print(f"PASS payload/{name} {actual}")

    for region, expected in EXPECTED_IPS.items():
        patch = (ROOT / "patches" / region / "code.ips").read_bytes()
        if sha(patch) != expected:
            raise RuntimeError(f"{region}: committed IPS hash mismatch")
        if not patch.startswith(b"PATCH") or not patch.endswith(b"EOF"):
            raise RuntimeError(f"{region}: malformed IPS framing")

        if args.input_dir:
            source = (args.input_dir / f"{region}.code.bin").read_bytes()
            info = REGIONS[region]
            if sha(source) != info["source_sha256"]:
                raise RuntimeError(f"{region}: unsupported source dump")
            expected_code = patch_code(source, info["google"], region)
            actual_code = apply_ips(source, patch)
            if actual_code != expected_code:
                raise RuntimeError(f"{region}: IPS round-trip mismatch")
            if sha(actual_code) != info["output_sha256"]:
                raise RuntimeError(f"{region}: output hash mismatch")
        print(f"PASS patches/{region}/code.ips {expected}")


if __name__ == "__main__":
    main()
