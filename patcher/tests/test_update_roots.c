#include "update_roots.h"
#include "sha256.h"
#include "roots.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    const char base[]="-----BEGIN CERTIFICATE-----\nold\n-----END CERTIFICATE-----\n";
    const char replacement[]="new base\n";
    const char extra[]="-----BEGIN CERTIFICATE-----\nextra\n-----END CERTIFICATE-----\n";
    uint8_t hashes[64]; sha256_buffer(base,strlen(base),hashes); memset(hashes+32,0,32);
    size_t size=strlen(replacement); uint8_t *bundle=malloc(size);
    memcpy(bundle,replacement,size);
    assert(!update_roots_merge((const uint8_t *)base,strlen(base),hashes,&bundle,&size));
    assert(size==strlen(replacement));
    char old[256]; strcpy(old,base); strcat(old,extra);
    assert(!update_roots_merge((const uint8_t *)old,strlen(old),hashes,&bundle,&size));
    assert(size==strlen(replacement)+strlen(extra));
    assert(!memcmp(bundle,replacement,strlen(replacement)));
    assert(!memcmp(bundle+strlen(replacement),extra,strlen(extra))); free(bundle);
    size=strlen(replacement); bundle=malloc(size); memcpy(bundle,replacement,size);
    old[30]='X';
    assert(update_roots_merge((const uint8_t *)old,strlen(old),hashes,&bundle,&size));
    assert(size==strlen(replacement) && !memcmp(bundle,replacement,size));
    uint8_t *large=malloc(strlen(base)+ROOT_EXTRA_LIMIT+1);
    memcpy(large,base,strlen(base)); memset(large+strlen(base),'x',ROOT_EXTRA_LIMIT+1);
    assert(update_roots_merge(large,strlen(base)+ROOT_EXTRA_LIMIT+1,hashes,&bundle,&size));
    assert(size==strlen(replacement)); free(large); free(bundle);
    puts("PASS update roots: fixed base, exact extra retention, changed base and excess size rejected"); return 0;
}
