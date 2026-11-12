# Certificates

[日本語](CERTIFICATES.ja.md)

The stock browser can parse many modern chains but lacks some EC operations
and current trust anchors. SKATER+ therefore:

1. lets the patched OpenSSL CRO handle TLS and ordinary certificate checks;
2. bridges missing P-256/P-384 public-key and signature operations to a small
   Mbed TLS component;
3. supplies a curated current `rootca.pem`.

## Adding your own roots

1. Put a self-signed CA certificate in `sd:/3ds/skater-plus-patcher/certs/`.
   Use PEM encoding, one certificate per file, with a lowercase `.pem` or `.crt`
   extension. DER files, private keys and certificate chains are rejected.
2. Open the patcher after installing SKATER+ and press **L**.
3. Check the subject and DER SHA-256 fingerprint against the CA's published
   information. Press **A** to trust the root or **B** to skip it.
4. Close and reopen the browser.

Mbed TLS checks the CA flag, certificate-signing usage, and self-signature.
Imported roots apply to all sites visited in this browser. Add only CAs you trust.
Duplicates are skipped. The limit is four extra roots, 8 KiB per input file,
and 16 KiB total.

Removing SKATER+ also removes the imported roots from the
browser. Source files in `certs/` are kept for later import.

To remove one imported root, press **R** in the patcher, select it with
**UP/DOWN**, check the subject and fingerprint, and press **A**. Built-in roots
and other imported roots are preserved. Reopen the browser afterward.

## Added roots

v0.1.1 adds these 26 roots. DigiCert Global Root G3 is new since v0.1.0.

- Security Communication RootCA2
- COMODO RSA Certification Authority
- USERTrust RSA Certification Authority
- IdenTrust Commercial Root CA 1
- ISRG Root X1
- Amazon Root CA 1
- Amazon Root CA 2
- SSL.com Root Certification Authority RSA
- SSL.com EV Root Certification Authority RSA R2
- GlobalSign Root CA - R6
- Microsoft RSA Root Certificate Authority 2017
- NAVER Global Root Certification Authority
- GlobalSign Root R46
- HARICA TLS RSA Root CA 2021
- GTS Root R1
- DigiCert Global Root G3
- DigiCert TLS RSA4096 Root G5
- Sectigo Public Server Authentication Root R46
- Sectigo Public Server Authentication Root E46
- SSL.com TLS RSA Root CA 2022
- Telekom Security TLS RSA Root 2023
- SecureSign Root CA14
- TrustAsia TLS RSA Root CA
- SwissSign RSA TLS Root CA 2022 - 1
- OISTE Server Root RSA G1
- Telia RSA TLS Root CA v3

The [root certificate sources](../vendor/root-certificates/README.md) and [third-party notices](../THIRD_PARTY_NOTICES.md) list provenance and licenses. The source hashes are pinned in `scripts/build_rootca_bundle.ps1`.
