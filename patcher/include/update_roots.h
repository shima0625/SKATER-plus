#pragma once
#include <stddef.h>
#include <stdint.h>

/* Caller verifies the existing whole-bundle registry before calling this. */
int update_roots_merge(const uint8_t *old,size_t old_size,const uint8_t bases[64],
                       uint8_t **bundle,size_t *size);
