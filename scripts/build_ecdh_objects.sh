#!/bin/sh
# ARM11 ECDH arithmetic, Thumb ABI wrapper; fixed integration address.
set -eu
prefix="${DEVKITARM:?DEVKITARM required}/bin/arm-none-eabi-"
test "$("${prefix}gcc" -dumpfullversion)" = 16.1.0
out=build/ecdh-arm
mkdir -p "$out"
flags="-Os -march=armv6k -mtune=mpcore -mfloat-abi=soft -ffunction-sections -fdata-sections -fno-builtin -fno-stack-protector -fshort-enums -fno-unwind-tables -fno-asynchronous-unwind-tables"
defs="-DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0 -DuECC_SUPPORT_COMPRESSED_POINT=0"
"${prefix}gcc" $flags -mthumb $defs -Ivendor/micro-ecc -c payload/ecdh.c -o "$out/wrapper.o"
"${prefix}gcc" $flags -marm $defs -DuECC_PLATFORM=3 -DuECC_OPTIMIZATION_LEVEL=3 -Ivendor/micro-ecc -c vendor/micro-ecc/uECC.c -o "$out/uECC.o"
"${prefix}gcc" -nostdlib -march=armv6k -mfloat-abi=soft \
    -Wl,--gc-sections,--emit-relocs,-Ttext=0x14CF98,-e,payload_ecdh \
    "$out/wrapper.o" "$out/uECC.o" -lgcc -o "$out/ecdh-arm.elf"
cp "$out/ecdh-arm.elf" payload/ecdh-arm.elf
