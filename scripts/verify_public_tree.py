#!/usr/bin/env python3
"""Reject private dumps and complete reconstructed files from the public tree."""

from __future__ import annotations

import hashlib
import argparse
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PREFIXES = ("input/", "build/", "backups/", "dist/", "patcher/build/", "docs/diagnostics/", ".codex/", ".agents/", ".yomiyasu/")
FORBIDDEN_SUFFIXES = (".cia", ".3dsx", ".cci", ".dmp", ".elf", ".smdh", ".code.bin", ".cro", ".cro.lex")
FORBIDDEN_EXACT = {"patcher/exheader.bin", "docs/publishing.md", "docs/publishing.ja.md"}
PRIVATE_DOC_STEMS = {"publishing", "tls_diagnostics", "js_engine_replacement", "web_compatibility"}
ALLOWED_SUFFIX_EXCEPTIONS = {"payload/certificate-bridge/ec_bridge.elf", "payload/ecdh-arm.elf", "payload/aes-gcm-arm.elf"}
KNOWN_COMPLETE_HASHES = {
    "EA80E68D35A669D3BC44FEE6F88D4A1CB9C55248AA81C2B1D1125D8A1FA17B4A",
    "0DA1A8231272D7A7F09AD504D8701B7929AA5A4B1C1391500C36D46AC1351B47",
    "D5E92FFA2ADDDDAB86E9577CB3751E359CA5646B93A6D27ED37AA5FB417CCBFE",
    "D5417762E5BA427A5A90FF7FA48A54D3418BF40B94EC941D2016C84B54EC8965",
    "0EBEC4B34E28179B70AEA23EB361DEE3760F82C1482CB3F14DBE6B6960048ADA",
    "D48122075C2F5996F77421842C24AD710FB3C99B7C2697CFBFDFCC9FB36384C7",
    "03BE5574D61BF53B5AACC72850D95F600DC68E97F501A9B72AE883A368EBE25A",
    "381298A8DB92BD25D0890DEC9D89C1DE6C1DC2B14FD299C83BE902AAD2342A26",
    "35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0",
    "8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914",
    "B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C",
    "7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4",
    "748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28",
    "7F61C754757192D242228E71D932FD60C5C33325341F6C0E1FA5F1B2E851AC7A",
    "1D9AD1106DF8FDB5A0DCB7F821F3822C1B2B4A74EE083BA9B472B149AF1CB6E3",
    "D2700A6FE9D5E9E8B9742223268EC24FFE2B263B1BE9E9F2E35CF0AABAE49AED",
    "1BBFF52D750F581363FAA6D040A298E87588BB4456408E0DC06B800FFA1A8705",
    "BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE",
    "EBECAE6102C521D86124E9154695F4E787B8ED336D1184C3632793232DE05214",
    "86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422",
    "3D7E053FB7B8AD425AB7C0AE4523B837163CA9D436F8BFE43C8FE730636D04E2",
    "77D8B6985442F74BDAD3655FD16D871BAFC0240AB4CF0B2902F1E089FCEB6865",
}


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--all-files', action='store_true', help='audit an exported release tree, including untracked files')
    args = parser.parse_args()
    names = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                   if p.is_file() and '.git' not in p.relative_to(ROOT).parts) if args.all_files else tracked_files()
    failures: list[str] = []
    for name in names:
        normalized = name.replace("\\", "/")
        lower = normalized.lower()
        doc_stem = Path(lower).name.removesuffix('.md').removesuffix('.ja')
        if lower.startswith(FORBIDDEN_PREFIXES) or lower in FORBIDDEN_EXACT or (lower.endswith('.md') and doc_stem in PRIVATE_DOC_STEMS):
            failures.append(f"forbidden private path: {normalized}")
            continue
        if lower.endswith(FORBIDDEN_SUFFIXES) and normalized not in ALLOWED_SUFFIX_EXCEPTIONS:
            failures.append(f"forbidden build/full-file artifact: {normalized}")
            continue
        path = ROOT / name
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            if digest in KNOWN_COMPLETE_HASHES:
                failures.append(f"known complete browser file: {normalized}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"PASS public tree: {len(names)} {'exported' if args.all_files else 'tracked'} files")


if __name__ == "__main__":
    main()
