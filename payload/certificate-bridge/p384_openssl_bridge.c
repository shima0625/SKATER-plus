#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Minimal ABI view of the bundled OpenSSL 1.0.2 structures. Offsets are
 * checked for the 32-bit ARM target below; this is not an OpenSSL 3 API. */
typedef struct { int length, type; unsigned char *data; long flags; } OSSLString;
typedef struct { const char *sn, *ln; int nid, length;
                 const unsigned char *data; int flags; } OSSLObject;
typedef struct { int type; union { void *ptr; OSSLObject *object; } value; } OSSLType;
typedef struct { OSSLObject *algorithm; OSSLType *parameter; } OSSLAlgor;
typedef struct { size_t length; char *data; size_t max; } OSSLBuffer;
typedef struct { void *entries; int modified; OSSLBuffer *bytes;
                 unsigned char *canon_enc; int canon_enclen; } OSSLName;
typedef struct { unsigned char *enc; long len; int modified; } OSSLEncoding;
typedef struct { OSSLAlgor *algor; OSSLString *public_key; void *pkey; } OSSLPubkey;
typedef struct {
    void *version, *serial; OSSLAlgor *signature; OSSLName *issuer;
    void *validity; OSSLName *subject; OSSLPubkey *key;
    void *issuer_uid, *subject_uid, *extensions; OSSLEncoding enc;
} OSSLCertInfo;
typedef struct { OSSLCertInfo *info; OSSLAlgor *sig_alg;
                 OSSLString *signature; } OSSLCert;
_Static_assert(sizeof(void *) == 4, "3DS ARM32 ABI required");
_Static_assert(offsetof(OSSLCertInfo, enc) == 0x28, "TBS offset");

extern int ec_verify_certificate_signature_parts(unsigned, unsigned, const unsigned char *, size_t,
                                                 const unsigned char *, size_t,
                                                 const unsigned char *, size_t);

static int oid_is(const OSSLObject *object, const unsigned char *oid, size_t len)
{
    return object && object->data && object->length == (int)len &&
           memcmp(object->data, oid, len) == 0;
}

static int name_equal(const OSSLName *a, const OSSLName *b)
{
    return a && b && a->canon_enc && b->canon_enc &&
           a->canon_enclen > 0 && a->canon_enclen <= 4096 &&
           a->canon_enclen == b->canon_enclen &&
           memcmp(a->canon_enc, b->canon_enc, (size_t)a->canon_enclen) == 0;
}

int p384_verify_pair(const OSSLCert *subject, const OSSLCert *issuer)
{
    static const unsigned char ecdsa_sha256[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};
    static const unsigned char ecdsa_sha384[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03};
    static const unsigned char ecdsa_sha512[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04};
    static const unsigned char ec_public_key[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01};
    static const unsigned char secp256r1[] = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    static const unsigned char secp384r1[] = {0x2b,0x81,0x04,0x00,0x22};
    if (!subject || !issuer || !subject->info || !issuer->info ||
        !subject->sig_alg || !subject->info->signature ||
        !subject->signature || !issuer->info->key ||
        !issuer->info->key->algor || !issuer->info->key->public_key)
        return 0;
    const OSSLCertInfo *si = subject->info, *ii = issuer->info;
    const OSSLAlgor *key_alg = ii->key->algor;
    const OSSLString *sig = subject->signature, *key = ii->key->public_key;
    unsigned bits = 0;
    if (key_alg->parameter && key_alg->parameter->type == 6) {
        if (oid_is(key_alg->parameter->value.object, secp256r1, sizeof(secp256r1)))
            bits = 256;
        else if (oid_is(key_alg->parameter->value.object, secp384r1, sizeof(secp384r1)))
            bits = 384;
    }
    /* The issuer curve does not determine the certificate signature hash.
     * For example RapidSSL TLS ECC CA G1 uses P-384 with SHA-256. */
    const unsigned char *sig_oid = NULL;
    unsigned digest_bits = 0;
    if (oid_is(subject->sig_alg->algorithm, ecdsa_sha256, sizeof(ecdsa_sha256))) {
        sig_oid = ecdsa_sha256; digest_bits = 256;
    } else if (oid_is(subject->sig_alg->algorithm, ecdsa_sha384, sizeof(ecdsa_sha384))) {
        sig_oid = ecdsa_sha384; digest_bits = 384;
    } else if (oid_is(subject->sig_alg->algorithm, ecdsa_sha512, sizeof(ecdsa_sha512))) {
        sig_oid = ecdsa_sha512; digest_bits = 512;
    }
    const size_t sig_oid_len = sizeof(ecdsa_sha256);
    if (!bits || !digest_bits ||
        !oid_is(subject->sig_alg->algorithm, sig_oid, sig_oid_len) ||
        !oid_is(si->signature->algorithm, sig_oid, sig_oid_len) ||
        /* RFC 5758: ECDSA signature AlgorithmIdentifier parameters absent. */
        subject->sig_alg->parameter || si->signature->parameter ||
        !oid_is(key_alg->algorithm, ec_public_key, sizeof(ec_public_key)) ||
        !key_alg->parameter || key_alg->parameter->type != 6 ||
        !name_equal(si->issuer, ii->subject) ||
        !si->enc.enc || si->enc.modified || si->enc.len <= 0 ||
        si->enc.len > 16384 || !sig->data || sig->length <= 0 ||
        sig->length > 256 || !key->data || key->length != (bits == 256 ? 65 : 97) ||
        ((unsigned long)key->flags & 7u) != 0)
        return 0;
    return ec_verify_certificate_signature_parts(bits, digest_bits, si->enc.enc, (size_t)si->enc.len,
                                                 sig->data, (size_t)sig->length,
                                                 key->data, (size_t)key->length);
}

