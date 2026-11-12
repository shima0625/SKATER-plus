#pragma once

#include <stddef.h>
#include <stdint.h>

int lz11_decompress(const uint8_t *input, size_t input_size, uint8_t **output, size_t *output_size);
int lz11_pack_literals(const uint8_t *data, size_t size, uint8_t **packed, size_t *packed_size);
int delta_apply(const uint8_t *patch, size_t patch_size, const uint8_t *source, size_t source_size,
                uint8_t **target, size_t *target_size);
