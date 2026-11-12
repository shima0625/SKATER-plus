#ifndef P384_OFFLINE_MBEDTLS_CONFIG_H
#define P384_OFFLINE_MBEDTLS_CONFIG_H

/* DER-only X.509 parsing and ECDSA P-256/P-384 signature verification. */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ECP_C
/* Use curve-specific prime reduction instead of generic MPI division. */
#define MBEDTLS_ECP_NIST_OPTIM
/* This component verifies public signatures; it never generates keys/signs. */
#define MBEDTLS_ECP_NO_INTERNAL_RNG
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PLATFORM_ZEROIZE_ALT
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

#include "mbedtls/check_config.h"
#endif
