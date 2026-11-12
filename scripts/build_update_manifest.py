#!/usr/bin/env python3
"""Generate the small release asset consumed by the on-console updater."""
from pathlib import Path
import hashlib
import re

ROOT = Path(__file__).resolve().parents[1]


def write_manifest(directory: Path) -> Path:
    header = (ROOT / 'patcher/include/update_manifest.h').read_text(encoding='utf-8')
    version = re.search(r'^#define SKATER_VERSION "(\d+\.\d+\.\d+)"$', header, re.M)[1]
    major, minor, micro = map(int, version.split('.'))
    encoded = int(re.search(r'^#define SKATER_TITLE_VERSION (\d+)$', header, re.M)[1])
    makefile = (ROOT / 'patcher/Makefile').read_text(encoding='utf-8')
    cia_version = int(re.search(r'^APP_TITLE_VERSION\s*:=\s*(\d+)$', makefile, re.M)[1])
    if major > 63 or minor > 63 or micro > 15 or encoded != (major << 10 | minor << 4 | micro) or encoded != cia_version:
        raise ValueError('Inconsistent release / CIA versions')
    lines = ['SKATER-UPDATE-1', version]
    for kind in ('cia', '3dsx'):
        data = (directory / f'skater-plus-patcher.{kind}').read_bytes()
        if not 0 < len(data) <= 16 * 1024 * 1024:
            raise ValueError('Release file outside updater size limit')
        lines.append(f'{kind} {len(data)} {hashlib.sha256(data).hexdigest()}')
    output = directory / 'update.txt'
    output.write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')
    return output


if __name__ == '__main__':
    print(write_manifest(ROOT / 'dist'))
