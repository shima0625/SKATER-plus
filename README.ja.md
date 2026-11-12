# SKATER+

[English](README.md)

New Nintendo 3DSのインターネットブラウザー（SKATER）に、TLS 1.2、ルート証明書、Webサイト互換性の修正を追加するパッチです。Luma3DSがブラウザー起動時にSDカードから読み込みます。

> [!CAUTION]
> **このプロジェクトのコードと文書の大部分は、生成AIの支援を受けて作成しました。**

## ダウンロード

- [CIA](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia)
- [3DSX](https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.3dsx)

<a href="https://github.com/shima0625/SKATER-plus/releases/latest/download/skater-plus-patcher.cia"><img src="docs/images/cia-qr.png" alt="" width="240" height="240"></a>

## 機能

- ECDHE-RSA/ECDHE-ECDSA AES-GCMを使うTLS 1.2
- P-256/P-384の証明書とハンドシェイク署名の検証
- [ルート証明書を26件追加](docs/CERTIFICATES.ja.md)
- パッチャーからSD上のルート証明書を追加
- iOS 7世代のMobile Safari UAとHTTPS版Google検索
- 日本版の初回設定を修正。実機ではセーブデータを編集せずに完了

Googleは標準のiOS 6世代のユーザーエージェントをサポート対象外と判定します。
iOS 7世代に変更した環境では、ログイン後に検索できることを確認しました。

## 仕組み

`code.ips`は、ブラウザーが読み込む暗号ライブラリーのファイル名、ユーザーエージェント、Google検索先、日本版の初回登録処理を変更します。Luma3DSは差し替え用のOpenSSLモジュール `os2.cro.lex` と、その識別情報を収めた `tlsfix.crr` を読み込みます。

TLS通信はブラウザー付属のOpenSSL 1.0.2をもとにしたモジュールが担当します。Mbed TLSはP-256/P-384公開鍵の解析とECDSA署名検証を補います。追加した認証局は `rootca.pem` に収めています。

日本版の初回登録では `sec.ifilter.jp` にHTTPで接続します。端末識別子と応答は暗号化されないため、信頼できるネットワークで初回設定を行ってください。

## 対応状況

| 地域 | Lumaフォルダー | 状況 |
| --- | --- | --- |
| JPN | `0004003000008802` | 実機で初回設定、Wikipedia、Google、Yahoo、証明書、UAを確認 |
| USA | `0004003000009402` | 実機テスターが地域判定・導入・Wikipedia・Yahoo.comを確認（v0.1.0） |
| KOR | `000400300000AE02` | Azaharで起動・UA確認。TLSは実機未確認 |
| EUR/AUS | `0004003000009D02` | EUR実機テスターが地域判定・導入・Wikipedia・Yahooを確認（v0.1.0） |

USA・EURは[コミュニティからの動作報告](https://www.reddit.com/r/3dshomebrew/comments/1xhlyu2/)です。今回のTLS高速化版はJPN実機で検証しており、USA・EURでの再試験はまだです。

中国・台湾版とOld Nintendo 3DSのSPIDERは対象外です。詳細は
[地域別の対応状況](docs/COMPATIBILITY.ja.md)を参照してください。

## インストール

New Nintendo 3DS系本体、最新の地域別ブラウザー更新、最新版Luma3DSが必要です。

1. 起動時に<kbd>Select</kbd>を押し、**Enable game patching**を有効にして、<kbd>Start</kbd>で保存します。
   パッチャーも起動時にこの設定を確認します。
2. CIAをインストールし、HOMEメニューから **SKATER+ Patcher** を起動します。3DSX版はHomebrew Launcherから起動します。
3. <kbd>A</kbd>を押します。地域（日本・北米・欧州/豪州・韓国）は自動判定されます。
   本体内の公式ブラウザーファイルを検証してから、SD上にLumaパッチを生成します。
4. CIA版では、インストール後にパッチャーを残すか削除するか選べます。3DSX版ではそのまま終了します。
5. ブラウザーを起動し、利用したいサイトで動作を確認します。

削除する場合はパッチャーを再度起動し、<kbd>Y</kbd>を押し、<kbd>A</kbd>で確認します。削除後の再起動は不要です。
同じ場所に別のファイルがある場合はバックアップしますが、自動では復元しません。

パッチャーCIA自体は、未適用時・適用済み時・エラー画面のいずれでも<kbd>X</kbd>から削除できます。

ルート証明書を追加するには、PEM形式の証明書を1件ずつ`.pem`または`.crt`ファイルにして
`sd:/3ds/skater-plus-patcher/certs/`へ置きます。パッチ導入済みの状態でパッチャーを起動し、
<kbd>L</kbd>を押して各証明書の名義とSHA-256を確認します。
詳細は[証明書](docs/CERTIFICATES.ja.md#独自のルート証明書を追加)を参照してください。
追加済み証明書を個別に削除する場合は<kbd>R</kbd>を押します。

## 更新

起動時にHTTPSのHEADリクエスト1回で最新の正式版タグを確認します。
新しい版への更新を選んだときだけ、サイズ・ハッシュの情報を取得します。
<kbd>Select</kbd>で再確認できます。
通信できない場合も通常のパッチ導入は続けられます。

更新後はパッチャーを終了して開き直します。旧版のブラウザーパッチがある場合は
<kbd>A</kbd>で直接更新します。登録済みの追加証明書を維持し、認識できる古い配置も移行します。
CIA版は導入済みパッチャーを更新し、3DSX版はHBLから起動したファイルを更新します。
v0.1.0からの初回更新は手動で導入してください。

日本版実機では、起動時の更新確認に1.62秒、SDへの書き込みを伴うパッチ適用に5.19秒、同じパッチの再適用に2.42秒かかりました。

## TLSの高速化

### 証明書検証の高速化

日本版New 3DS実機で、ローカルサーバーへのTLS接続にかかる時間を比較しました。TLSセッションの再利用は除外しています。

| 発行者の鍵／接続時の認証 | 高速化前 | 高速化後 | 短縮率 |
| --- | ---: | ---: | ---: |
| P-256 / RSA | 916 ms | 402 ms | 56.0% |
| P-256 / ECDSA | 1,311 ms | 312 ms | 76.2% |
| P-384 / RSA | 1,558 ms | 320 ms | 79.4% |
| P-384 / ECDSA | 2,174 ms | 427 ms | 80.4% |

### AES-GCMの高速化

同じ実機で、1 MiBのデータを受信し始めてから完了するまでの時間を比較しました。表の値は各条件の中央値です。

| 接続時の認証／暗号方式 | 高速化前 | 高速化後 | 短縮率 |
| --- | ---: | ---: | ---: |
| RSA / AES-128-GCM | 573 ms | 454.5 ms | 20.7% |
| RSA / AES-256-GCM | 637 ms | 482 ms | 24.3% |
| ECDSA / AES-128-GCM | 602 ms | 486 ms | 19.3% |
| ECDSA / AES-256-GCM | 603 ms | 523.5 ms | 13.2% |

## スクリーンショット

| Wikipedia | Google | Yahoo.com |
| --- | --- | --- |
| ![HTTPS版Wikipedia](docs/images/wikipedia.png) | ![Google検索](docs/images/google.png) | ![Yahoo.com](docs/images/yahoo-com.png) |

## ビルド

パッチャーのビルドには同梱の実行用アセットを使います。ブラウザーパッチを再生成する場合は本体から取得したファイルが必要です。
手順は[ビルドガイド](docs/BUILDING.ja.md)に記載しています。

## 不具合報告

開けるサイトは、ブラウザーのJavaScript、HTML/CSS、対応コーデック、TLS機能に左右されます。

報告には本体の地域・機種、システムとLuma3DSのバージョン、ブラウザーのタイトルID、URL、エラー番号、パッチ適用前の結果を添えてください。

## ライセンス

独自コードはMITです。第三者ライセンスは
[THIRD_PARTY_NOTICES.ja.md](THIRD_PARTY_NOTICES.ja.md)を参照してください。
