#include "update_manifest.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char good[]="SKATER-UPDATE-1\n0.1.2\ncia 1234 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n3dsx 5678 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n";

int main(void) {
    SkaterUpdate value,unchanged; memset(&unchanged,0xa5,sizeof(unchanged));
    assert(!skater_update_parse(good,strlen(good),&value));
    assert(value.title_version==18 && !strcmp(value.version,"0.1.2"));
    assert(value.size[0]==1234 && value.size[1]==5678 && value.sha256[0][0]==1);
    unsigned checks=1;
    assert(!skater_update_tag("v0.1.1",6,&value) && value.title_version==17); checks++;
    const char *bad_tags[]={"0.1.1","v00.1.1","v0.1.16","v64.1.1","v0.1.1-beta","v0.1.1?x","v0.1.1/","v-1.1.1","v0.1.99999999999999999999999999999999"};
    for (unsigned i=0;i<sizeof(bad_tags)/sizeof(bad_tags[0]);i++) {
        value=unchanged; assert(skater_update_tag(bad_tags[i],strlen(bad_tags[i]),&value));
        assert(!memcmp(&value,&unchanged,sizeof(value))); checks++;
    }
    /* Every truncated prefix must fail and leave the output untouched. */
    for (size_t n=0;n<strlen(good);n++) {
        value=unchanged; assert(skater_update_parse(good,n,&value));
        assert(!memcmp(&value,&unchanged,sizeof(value))); checks++;
    }
    const char *bad[]={"", "SKATER-UPDATE-1\n999999999999999999999999999999.1.2\n",
                      "SKATER-UPDATE-1\n64.1.2\n", "SKATER-UPDATE-1\n0.64.2\n",
                      "SKATER-UPDATE-1\n0.1.16\n", "SKATER-UPDATE-1\n+0.1.2\n",
                      "SKATER-UPDATE-1\n00.1.2\n"};
    for (unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) { assert(skater_update_parse(bad[i],strlen(bad[i]),&value)); checks++; }
    char buf[1024];
    for (unsigned n=0;n<strlen(good);n++) {
        memcpy(buf,good,sizeof(good)); buf[n]=0;
        assert(skater_update_parse(buf,strlen(good),&value)); checks++;
    }
    strcpy(buf,good); strcat(buf,"extra\n"); assert(skater_update_parse(buf,strlen(buf),&value)); checks++;
    strcpy(buf,good); *strstr(buf,"1234")='-'; assert(skater_update_parse(buf,strlen(buf),&value)); checks++;
    memset(buf,'A',sizeof(buf)); assert(skater_update_parse(buf,sizeof(buf),&value)); checks++;
    assert(skater_update_parse(NULL,1,&value)); assert(skater_update_parse(good,strlen(good),NULL)); checks+=2;
    printf("PASS update manifest: %u checks\n",checks); return 0;
}
