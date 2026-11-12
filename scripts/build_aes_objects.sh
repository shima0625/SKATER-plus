#!/bin/sh
set -eu
prefix="${DEVKITARM:?DEVKITARM required}/bin/arm-none-eabi-"
test "$("${prefix}gcc" -dumpfullversion)" = 16.1.0
src=$(realpath vendor/openssl-arm)
out=build/aes-gcm-arm
mkdir -p "$out"
(cd "$out"; perl "$src/aes-armv4.pl" aes-arm.S; perl "$src/ghash-armv4.pl" ghash-arm.S)
"${prefix}gcc" -c -march=armv6k -marm -mfloat-abi=soft -I"$src" "$out/aes-arm.S" -o "$out/aes-arm.o"
"${prefix}gcc" -c -march=armv6k -marm -mfloat-abi=soft -I"$src" "$out/ghash-arm.S" -o "$out/ghash-arm.o"
"${prefix}gcc" -c -O2 -march=armv6k -marm -mfloat-abi=soft -ffreestanding -fno-builtin payload/ghash_adapter.c -o "$out/adapter.o"
"${prefix}gcc" -nostdlib -march=armv6k -mfloat-abi=soft \
    -Wl,--gc-sections,--emit-relocs,-Ttext=0x14E7B0,-e,AES_encrypt,-u,skater_gmult \
    "$out/aes-arm.o" "$out/ghash-arm.o" "$out/adapter.o" -o "$out/aes-gcm-arm.elf"
cp "$out/aes-gcm-arm.elf" payload/aes-gcm-arm.elf
