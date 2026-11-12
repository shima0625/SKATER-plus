#!/usr/bin/env python3
"""Reproduce the small public CA set used by the GitHub updater."""
from pathlib import Path
import hashlib
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
WANTED = (
    'Sectigo Public Server Authentication Root E46',
    'Sectigo Public Server Authentication Root R46',
    'USERTrust RSA Certification Authority',
    'USERTrust ECC Certification Authority',
    'ISRG Root X1', 'ISRG Root X2',
    'DigiCert Global Root G2', 'DigiCert Global Root G3',
)


def main():
    source = ROOT / 'vendor/root-certificates/mozilla-cacert-2026-09-25.pem'
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest().upper() != 'A41B5D356AEA97A529FE27E0F7316D2F9D946D75927476CF9CF1B90637D00505':
        raise ValueError('Unexpected CA snapshot')
    certs = {c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value: c
             for c in x509.load_pem_x509_certificates(data)
             if c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)}
    result = b'# GitHub updater trust anchors; Mozilla CA Extract 2026-09-25 subset.\n# Source: vendor/root-certificates/mozilla-cacert-2026-09-25.pem\n# Mozilla Public License 2.0: https://www.mozilla.org/MPL/2.0/\n\n'
    for name in WANTED:
        result += ('# ' + name + '\n').encode() + certs[name].public_bytes(Encoding.PEM) + b'\n'
    output = ROOT / 'patcher/romfs/assets/updater-ca.pem'
    output.write_bytes(result)
    print(f'{len(WANTED)} roots, {len(result)} bytes, SHA256 {hashlib.sha256(result).hexdigest()}')


if __name__ == '__main__':
    main()
