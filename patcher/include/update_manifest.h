#pragma once
#include <stddef.h>
#include <stdint.h>

#define SKATER_VERSION "0.1.1"
#define SKATER_TITLE_VERSION 17
#define SKATER_UPDATE_MAX_FILE (16u * 1024u * 1024u)
#define SKATER_UPDATE_MAX_MANIFEST 512

typedef struct {
    char version[24];
    uint16_t title_version;
    size_t size[2]; /* CIA, 3DSX */
    uint8_t sha256[2][32];
} SkaterUpdate;

/* Strict, bounded release metadata; URLs are constructed locally, never supplied. */
int skater_update_parse(const char *text, size_t size, SkaterUpdate *out);
int skater_update_tag(const char *text,size_t size,SkaterUpdate *out);
