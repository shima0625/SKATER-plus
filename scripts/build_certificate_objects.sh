#!/bin/sh
# Build the ARM11 certificate verifier from an unpacked Mbed TLS 2.28.8 tree.
set -eu
mbed="${1:?usage: build_certificate_objects.sh /path/to/mbedtls-2.28.8}"
prefix="${DEVKITARM:-/opt/devkitpro/devkitARM}/bin/arm-none-eabi-"
cc="${prefix}gcc"
test "$("$cc" -dumpfullversion)" = 16.1.0 || { echo 'devkitARM GCC 16.1.0 required' >&2; exit 1; }
grep -q '^#define MBEDTLS_VERSION_STRING *"2.28.8"' "$mbed/include/mbedtls/version.h" || { echo 'Mbed TLS 2.28.8 required' >&2; exit 1; }
out=build/certificate-bridge
src=payload/certificate-bridge
mkdir -p "$out"
flags="-Os -mthumb -march=armv6k -mtune=mpcore -mfloat-abi=soft -ffunction-sections -fdata-sections -fno-builtin -fno-stack-protector -fshort-enums"
objects=""
for name in asn1parse asn1write bignum constant_time ecdsa ecp ecp_curves md oid pk pk_wrap pkparse platform_util rsa rsa_internal sha256 sha512 x509 x509_crt; do
    "$cc" $flags -I"$src" -I"$mbed/include" -DMBEDTLS_CONFIG_FILE='"mbedtls_minimal_config.h"' -c "$mbed/library/$name.c" -o "$out/$name.o"
    objects="$objects $out/$name.o"
done
rm -f "$out/libec.a"
"${prefix}ar" rcs "$out/libec.a" $objects
for name in p384_openssl_bridge p384_signature_fallback ec_public_key ec_tls_verify p384_runtime_bridge; do
    "$cc" $flags -Wall -Wextra -Werror -I"$src" -I"$mbed/include" -DMBEDTLS_CONFIG_FILE='"mbedtls_minimal_config.h"' -c "$src/$name.c" -o "$out/$name.o"
done
"$cc" -c -mthumb -march=armv6k -mfloat-abi=soft "$src/p384_hook.S" -o "$out/hook.o"
"$cc" -nostdlib -mthumb -march=armv6k -mfloat-abi=soft \
    -Wl,--gc-sections,--emit-relocs,-Ttext=0x146B00,-e,p384_hook_thumb,-Map="$out/ec_bridge.map" \
    -Wl,-u,ec_asn1_method,-u,ec_cert_type_hook,-u,ec_tls_verify_final \
    -Wl,--defsym=stock_signature_verified_thumb=0x1E4EF,--defsym=stock_X509_get_pubkey_thumb=0xB9B69 \
    -Wl,--defsym=stock_crypto_malloc_thumb=0xBB48D,--defsym=stock_crypto_free_thumb=0xBB459 \
    -Wl,--defsym=stock_cert_type_done_thumb=0x977A3,--defsym=stock_cert_type_gost94_thumb=0x9777B \
    -Wl,--defsym=browser_md_ctx_init=0x97B21,--defsym=browser_md_ctx_copy=0xA3431 \
    -Wl,--defsym=browser_md_final=0xAAEF9,--defsym=browser_md_ctx_cleanup=0x97AAD,--defsym=browser_verify_final=0x5780D \
    "$out/hook.o" "$out/p384_openssl_bridge.o" "$out/p384_signature_fallback.o" \
    "$out/ec_public_key.o" "$out/ec_tls_verify.o" "$out/p384_runtime_bridge.o" \
    "$out/libec.a" -lc -lgcc -o "$out/ec_bridge.elf"
cp "$out/ec_bridge.elf" "$src/ec_bridge.elf"
