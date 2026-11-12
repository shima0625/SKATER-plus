#include <stddef.h>
#include <string.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)
void mbedtls_platform_zeroize(void *buffer, size_t length)
{
    volatile unsigned char *bytes = (volatile unsigned char *)buffer;
    while (length--) *bytes++ = 0;
}
#endif

/* Shared EC primitives for the prospective X509_PUBKEY decoder and the
 * ServerKeyExchange ECDSA signature verifier. No trust decisions here. */
int ec_validate_public_point(unsigned bits, const unsigned char *point,
                             size_t point_len)
{
    mbedtls_ecdsa_context ec;
    int valid = 0;
    if (!point || point[0] != 4 ||
        !((bits == 256 && point_len == 65) ||
          (bits == 384 && point_len == 97)))
        return 0;
    mbedtls_ecdsa_init(&ec);
    mbedtls_ecp_group_id id = bits == 256 ? MBEDTLS_ECP_DP_SECP256R1 :
                                           MBEDTLS_ECP_DP_SECP384R1;
    valid = mbedtls_ecp_group_load(&ec.grp, id) == 0 &&
            mbedtls_ecp_point_read_binary(&ec.grp, &ec.Q, point, point_len) == 0 &&
            mbedtls_ecp_check_pubkey(&ec.grp, &ec.Q) == 0;
    mbedtls_ecdsa_free(&ec);
    return valid;
}

int ec_verify_digest_point(unsigned bits, const unsigned char *point,
                           size_t point_len, const unsigned char *digest,
                           size_t digest_len, const unsigned char *signature,
                           size_t signature_len)
{
    mbedtls_ecdsa_context ec;
    int valid = 0;
    if (!digest || !signature || !signature_len || signature_len > 144 ||
        !(digest_len == 32 || digest_len == 48 || digest_len == 64) ||
        !((bits == 256 && point_len == 65) ||
          (bits == 384 && point_len == 97)))
        return 0;
    mbedtls_ecdsa_init(&ec);
    mbedtls_ecp_group_id id = bits == 256 ? MBEDTLS_ECP_DP_SECP256R1 :
                                           MBEDTLS_ECP_DP_SECP384R1;
    valid = mbedtls_ecp_group_load(&ec.grp, id) == 0 &&
            mbedtls_ecp_point_read_binary(&ec.grp, &ec.Q, point, point_len) == 0 &&
            mbedtls_ecp_check_pubkey(&ec.grp, &ec.Q) == 0 &&
            mbedtls_ecdsa_read_signature(&ec, digest, digest_len,
                                         signature, signature_len) == 0;
    mbedtls_ecdsa_free(&ec);
    return valid;
}

/* Inputs are the original signed TBS DER, DER-encoded ECDSA signature,
 * and the issuer's uncompressed P-256/P-384 public point. This form can be
 * populated from OpenSSL 1.0.2's cached ASN1_ENCODING and X509_PUBKEY,
 * without asking its unsupported EC decoder to construct an EVP_PKEY. */
int ec_verify_certificate_signature_parts(unsigned bits, unsigned digest_bits,
                                          const unsigned char *tbs, size_t tbs_len,
                                          const unsigned char *sig, size_t sig_len,
                                          const unsigned char *point, size_t point_len)
{
    mbedtls_ecdsa_context ec;
    /* The SHA-384 API writes into a 64-byte SHA-512-sized buffer. */
    unsigned char hash[64];
    int valid = 0;
    mbedtls_ecdsa_init(&ec);
    if (!tbs || !sig || !point || !tbs_len || tbs_len > 16384 ||
        !sig_len || sig_len > 144 ||
        !(digest_bits == 256 || digest_bits == 384 || digest_bits == 512) ||
        !((bits == 256 && point_len == 65) ||
          (bits == 384 && point_len == 97)) || point[0] != 4)
        goto done;
    if (mbedtls_ecp_group_load(&ec.grp, bits == 256 ? MBEDTLS_ECP_DP_SECP256R1 :
                                                         MBEDTLS_ECP_DP_SECP384R1) != 0 ||
        mbedtls_ecp_point_read_binary(&ec.grp, &ec.Q, point, point_len) != 0 ||
        mbedtls_ecp_check_pubkey(&ec.grp, &ec.Q) != 0)
        goto done;
    if (digest_bits == 256 ? mbedtls_sha256_ret(tbs, tbs_len, hash, 0) != 0 :
                            mbedtls_sha512_ret(tbs, tbs_len, hash, digest_bits == 384) != 0)
        goto done;
    valid = mbedtls_ecdsa_read_signature(&ec, hash, digest_bits / 8,
                                         sig, sig_len) == 0;
done:
    mbedtls_ecdsa_free(&ec);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return valid;
}

/*
 * Verify one certificate signature, not a complete trust decision. The caller
 * must retain its existing chain building, trust-anchor, time, usage and host
 * checks. Return 1 only for a valid P-384 ECDSA issuer/signature pair.
 */
int p384_verify_cert_signature(const unsigned char *subject_der,
                               size_t subject_len,
                               const unsigned char *issuer_der,
                               size_t issuer_len)
{
    mbedtls_x509_crt subject, issuer;
    mbedtls_x509_crt_init(&subject);
    mbedtls_x509_crt_init(&issuer);
    int valid = 0;
    if (!subject_der || !issuer_der || subject_len == 0 || issuer_len == 0 ||
        subject_len > 16384 || issuer_len > 16384)
        goto done;
    if (mbedtls_x509_crt_parse_der(&subject, subject_der, subject_len) != 0 ||
        mbedtls_x509_crt_parse_der(&issuer, issuer_der, issuer_len) != 0)
        goto done;
    if (subject.sig_pk != MBEDTLS_PK_ECDSA ||
        mbedtls_pk_get_type(&issuer.pk) != MBEDTLS_PK_ECKEY ||
        mbedtls_pk_ec(issuer.pk)->grp.id != MBEDTLS_ECP_DP_SECP384R1 ||
        subject.issuer_raw.len != issuer.subject_raw.len ||
        memcmp(subject.issuer_raw.p, issuer.subject_raw.p,
               subject.issuer_raw.len) != 0)
        goto done;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(subject.sig_md);
    if (!md || mbedtls_md_get_size(md) > MBEDTLS_MD_MAX_SIZE)
        goto done;
    unsigned char digest[MBEDTLS_MD_MAX_SIZE];
    if (mbedtls_md(md, subject.tbs.p, subject.tbs.len, digest) == 0 &&
        mbedtls_pk_verify(&issuer.pk, subject.sig_md, digest,
                          mbedtls_md_get_size(md), subject.sig.p,
                          subject.sig.len) == 0)
        valid = 1;
done:
    mbedtls_x509_crt_free(&issuer);
    mbedtls_x509_crt_free(&subject);
    return valid;
}
