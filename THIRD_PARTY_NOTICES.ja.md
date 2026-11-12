# 第三者ライセンス

[English](THIRD_PARTY_NOTICES.md)

SKATER+で使うライブラリーと証明書の出典です。

- Mbed TLS 2.28.8：証明書検証ブリッジと、devkitProの`3ds-mbedtls`経由でSD証明書取り込みに使用（Apache-2.0）
- micro-ecc：ECDHE処理で使用（BSD 2-Clause）
- OpenSSLのARM向けAES/GHASH：転送処理の高速化に使用。出典と完全なライセンスは
  `vendor/openssl-arm/`にあり、ライセンスはCIA/3DSXのRomFSにも含めます。
- Mozilla CA Certificate Program data：ルート証明書の元データ（MPL 2.0）
- Sectigo Public Server Authentication Root E46：Sectigoが公開するルート証明書

完全なライセンスは`vendor/mbedtls/LICENSE`と`vendor/micro-ecc/LICENSE.txt`、
証明書の出典は`vendor/root-certificates/README.md`にあります。

SKATER+はLuma3DS、OpenSSL、Nintendo 3DSシステムと相互運用しますが、これらの開発元や
権利者がSKATER+を推奨または承認しているわけではありません。任天堂の標準ファイルは
本リポジトリに含めません。

- **curl 8.4.0**と**zlib 1.3.1** — devkitPro portlibs経由でHTTPS更新に使用。ライセンス全文を`patcher/romfs/licenses/`に同梱しています。更新時の証明書検証には固定したMozilla CA一覧を使います。
