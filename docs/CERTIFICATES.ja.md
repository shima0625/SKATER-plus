# 証明書

[English](CERTIFICATES.md)

標準ブラウザーは多くの証明書チェーンを読めますが、一部の楕円曲線処理と現在の
信頼済みルートが不足しています。そこで、次の3段階で補います。

1. 修正済みOpenSSL CROがTLS通信と通常の証明書検証を担当します。
2. 不足するP-256/P-384公開鍵の解析とECDSA署名検証だけをMbed TLSへ渡します。
3. 下記のルート証明書を `rootca.pem` に追加します。

## 独自のルート証明書を追加

1. 自己署名CA証明書を`sd:/3ds/skater-plus-patcher/certs/`へ置きます。
   PEM形式で1ファイル1証明書とし、拡張子は小文字の`.pem`または`.crt`にします。
   DER形式、秘密鍵、複数証明書入りのファイルは取り込めません。
2. SKATER+導入後にパッチャーを起動し、**L**を押します。
3. 表示された名義とDERのSHA-256を認証局の公開情報と照合し、**A**で追加、**B**でスキップします。
4. ブラウザーを閉じて開き直します。

パッチャーはMbed TLSでCA属性、証明書署名の用途、自己署名を検証します。追加した認証局は、ブラウザーで開くすべてのサイトの検証に使われます。信頼できる認証局だけを追加してください。
重複はスキップします。上限は追加4件、入力1ファイル8KiB、合計16KiBです。

SKATER+を削除するとブラウザー用に追加した証明書も消えますが、`certs/`の元ファイルは残ります。

1件だけ削除するにはパッチャーで**R**を押し、**上下キー**で選び、名義とSHA-256を確認して**A**を押します。
標準の証明書と他の追加済み証明書は残ります。削除後はブラウザーを開き直してください。

## 追加するルート証明書

v0.1.1では次の26件を追加します。v0.1.0からはDigiCert Global Root G3が増えました。

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

証明書の取得元とハッシュは `scripts/build_rootca_bundle.ps1` に記載しています。出典とライセンスは [ルート証明書の出典](../vendor/root-certificates/README.md) と [第三者ライセンス](../THIRD_PARTY_NOTICES.ja.md) を参照してください。
