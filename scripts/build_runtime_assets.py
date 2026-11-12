#!/usr/bin/env python3
"""Build redistributable runtime assets for the on-console patcher.

The resulting CRO delta contains copy instructions into the user's own stock
CRO plus short literal runs.  It does not contain a complete Nintendo module.
"""

from __future__ import annotations

import hashlib
import shutil
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "input" / "oss.cro"
TARGET = ROOT / "build" / "oss-skaterplus.cro"
STOCK_ROOTS = ROOT / "input" / "rootca.pem"
TARGET_ROOTS = ROOT / "build" / "rootca.pem"
ASSETS = ROOT / "patcher" / "romfs" / "assets"

SOURCE_SHA256 = "BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE"
TARGET_SHA256 = "EA80E68D35A669D3BC44FEE6F88D4A1CB9C55248AA81C2B1D1125D8A1FA17B4A"
STOCK_ROOTS_SHA256 = "3D7E053FB7B8AD425AB7C0AE4523B837163CA9D436F8BFE43C8FE730636D04E2"
TARGET_ROOTS_SHA256 = "35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def make_delta(source: bytes, target: bytes) -> bytes:
    # CRO structures and code are naturally word aligned. Indexing every
    # source word keeps generation fast while still finding all large runs.
    anchor = 12
    index: dict[bytes, list[int]] = {}
    for pos in range(0, len(source) - anchor + 1, 4):
        positions = index.setdefault(source[pos:pos + anchor], [])
        if len(positions) < 16:
            positions.append(pos)

    commands: list[tuple[int, int, bytes | int]] = []
    literals = bytearray()

    def flush_literals() -> None:
        if literals:
            commands.append((1, len(literals), bytes(literals)))
            literals.clear()

    pos = 0
    while pos < len(target):
        best_start = -1
        best_len = 0
        if pos + anchor <= len(target):
            for candidate in index.get(target[pos:pos + anchor], ()):
                length = anchor
                limit = min(len(source) - candidate, len(target) - pos)
                while length + 8 <= limit and source[candidate + length:candidate + length + 8] == target[pos + length:pos + length + 8]:
                    length += 8
                while length < limit and source[candidate + length] == target[pos + length]:
                    length += 1
                if length > best_len:
                    best_start, best_len = candidate, length
        if best_len >= 24:
            flush_literals()
            commands.append((0, best_len, best_start))
            pos += best_len
        else:
            literals.append(target[pos])
            pos += 1
    flush_literals()

    out = bytearray(b"SKD1")
    out += struct.pack("<III", len(source), len(target), len(commands))
    out += hashlib.sha256(source).digest()
    out += hashlib.sha256(target).digest()
    for kind, length, payload in commands:
        out += struct.pack("<BI", kind, length)
        if kind == 0:
            out += struct.pack("<I", payload)
        else:
            out += payload
    return bytes(out)


def main() -> None:
    source = SOURCE.read_bytes()
    target = TARGET.read_bytes()
    if digest(source) != SOURCE_SHA256 or digest(target) != TARGET_SHA256:
        raise SystemExit("CRO input hash mismatch; rebuild the verified payload first")

    stock_roots = STOCK_ROOTS.read_bytes()
    target_roots = TARGET_ROOTS.read_bytes()
    if digest(stock_roots) != STOCK_ROOTS_SHA256 or digest(target_roots) != TARGET_ROOTS_SHA256:
        raise SystemExit("root certificate bundle hash mismatch")
    prefix = stock_roots.rstrip()
    if not target_roots.startswith(prefix):
        raise SystemExit("target root bundle is not stock bundle plus an append-only suffix")

    ASSETS.mkdir(parents=True, exist_ok=True)
    delta = make_delta(source, target)
    (ASSETS / "oss.delta").write_bytes(delta)
    (ASSETS / "rootca.append").write_bytes(target_roots[len(prefix):])
    for region in ("JPN", "USA", "EUR", "KOR"):
        destination = ASSETS / region
        destination.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "patches" / region / "code.ips", destination / "code.ips")

    print(f"oss.delta={len(delta)} bytes ({len(delta) / len(target):.1%} of target)")
    print(f"rootca.append={len(target_roots) - len(prefix)} bytes")


if __name__ == "__main__":
    main()
