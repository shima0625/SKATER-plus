#include "update_roots.h"
#include "sha256.h"
#include "roots.h"
#include <stdlib.h>
#include <string.h>

static int recognized(const uint8_t *data,size_t size,const uint8_t bases[64]) {
    uint8_t hash[32]; sha256_buffer(data,size,hash);
    return !memcmp(hash,bases,32) || !memcmp(hash,bases+32,32);
}

int update_roots_merge(const uint8_t *old,size_t n,const uint8_t bases[64],uint8_t **bundle,size_t *size) {
    if (!old || !bases || !bundle || !*bundle || !size || n>131072 || *size>131072) return -1;
    if (recognized(old,n,bases)) return 0;
    size_t base=0;
    const char end[]="-----END CERTIFICATE-----"; size_t marker=sizeof(end)-1;
    for (size_t i=0;i+marker<=n && !base;i++) if (!memcmp(old+i,end,marker)) {
        size_t j=i+marker;
        do {
            if (recognized(old,j,bases)) { base=j; break; }
            if (j>=n || !(old[j]==' ' || old[j]=='\t' || old[j]=='\r' || old[j]=='\n')) break;
            j++;
        } while (1);
    }
    if (!base || n-base>ROOT_EXTRA_LIMIT) return -1;
    uint8_t *next=realloc(*bundle,*size+n-base);
    if (!next) return -1;
    memcpy(next+*size,old+base,n-base); *bundle=next; *size+=n-base; return 0;
}
