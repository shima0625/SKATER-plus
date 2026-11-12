# SKATER+のビルド

[English](BUILDING.md)

## パッチャーのビルド

通常のビルドには同梱の実行用アセットを使います。
devkitARM、libctru、makeromとdevkitProの`3ds-mbedtls`・`3ds-curl`・`3ds-zlib`を導入して、次を実行します。

```text
make -C patcher
make -C patcher cia MAKEROM=makerom
python scripts/package_releases.py
```

## ブラウザーパッチの再生成

自分の本体から取得した次の対応ファイルを`input/`へ置きます。

| ファイル | SHA-256 |
| --- | --- |
| `JPN.code.bin` | `8B06E7D18DF8D9DFFFF161D26D3213A2C474888C35491CF0C96C709931C8D914` |
| `USA.code.bin` | `B2BD118F99D7FAF424A720B63004F92EDB299354989BA143EFA42B50144CE41C` |
| `KOR.code.bin` | `7308CE1B326AECA2A5BF468D7ACF661F5B5135E7F77A6FE355C8EF41D00158B4` |
| `EUR.code.bin` | `748A5C276D3729F59BDD61541FC66DC5F78C23776BEABB982839522ABC729F28` |
| `oss.cro` | `BDD428C371717B0741CCFC118BABB355BFB6D2F3585BACE2E4DDEEE2723C87DE` |

対応する0x1000バイトの`static.crr`も必要です。ルート証明書束を再生成する場合は、
対応する標準`rootca.pem`も用意してください。

リポジトリ直下で次を実行します。

```powershell
python scripts/build_regional_tls_packages.py --input-dir input
python scripts/verify_regional_tls_build.py --input-dir input
python scripts/build_ecdhe_static_patch.py
sh scripts/build_certificate_objects.sh /path/to/mbedtls-2.28.8
python scripts/build_certificate_bridge.py
sh scripts/build_ecdh_objects.sh
python scripts/build_ecdh_acceleration.py
sh scripts/build_aes_objects.sh
python scripts/build_aes_acceleration.py
python scripts/build_matching_crr.py
pwsh -File scripts/build_rootca_bundle.ps1 -StockPath input/rootca.pem -OutputPath build/rootca.pem
python scripts/build_runtime_assets.py
```

`package_releases.py`はパッチャーのCIAと3DSXを配布用にまとめます。

主要な出力のSHA-256は次のとおりです。

| 出力 | SHA-256 |
| --- | --- |
| `build/oss-skaterplus.cro.lex` | `0DA1A8231272D7A7F09AD504D8701B7929AA5A4B1C1391500C36D46AC1351B47` |
| `build/tlsfix.crr` | `86712C50A3E4C6256D8CC81A4B61331D6E9A1C46676941E0064289FF811F5422` |
| `build/rootca.pem` | `35BE1BEB9AC3B17F128C16792DAE3CE0FBE0230A7C8AA2D47E500084F4F7E7F0` |

未対応の入力、変更位置の不一致、出力ハッシュの不一致があれば停止します。

`build_runtime_assets.py`は`patcher/romfs/assets/`の差分を更新します。
更新後、上記の手順でパッチャーを再ビルドします。

証明書モジュールのビルドにはdevkitARM GCC 16.1.0とMbed TLS 2.28.8のソースを使います。
`sh`のコマンドはLinux/devkitPro環境で実行してください。
`python scripts/emulate_certificate_bridge.py`で組み込み後のCROを検証できます。
必要なPythonライブラリーはUnicorn 2.1.4とcryptography 48.0.1です。
CIは`--elf-only`を使うため、ブラウザーダンプは不要です。

更新機能はcurl 8.4以降とMbed TLSを使います。更新用CA一覧は、固定したMozilla一覧から8件を選んだものを登録しています。`python scripts/build_updater_ca.py`で再生成できます。`package_releases.py`はCIA・3DSXと、それぞれのサイズ・SHA-256を記録した更新用`update.txt`を生成します。CIA・3DSX・更新情報は、同じバージョンの組み合わせで使います。

パッケージ作成時はCIAのチケットとTMDの版を検査します。古いProject_CTR makeromでは`VER_MAJOR`・`VER_MINOR`の名前が衝突します。検査に失敗する場合はmakeromのソースディレクトリで`scripts/makerom-version.patch`を適用し、ツールを再ビルドしてください。版の検査は省略しないでください。
