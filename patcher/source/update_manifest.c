#include "update_manifest.h"
#include <stdio.h>
#include <string.h>

static int hex(unsigned char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}

static int number(const char **cursor,unsigned long limit,unsigned long *out,char separator) {
    const char *p=*cursor; unsigned long value=0;
    if (*p<'0' || *p>'9' || (*p=='0' && p[1]!=separator)) return -1;
    do {
        unsigned digit=(unsigned)(*p++-'0');
        if (value>(limit-digit)/10 || digit>limit) return -1;
        value=value*10+digit;
    } while (*p>='0' && *p<='9');
    if (*p++!=separator) return -1;
    *cursor=p; *out=value; return 0;
}

int skater_update_tag(const char *text,size_t size,SkaterUpdate *out) {
    if (!text || !out || size<6 || size>=24 || text[0]!='v' || memchr(text,0,size)) return -1;
    char buf[24]; memcpy(buf,text,size); buf[size]=0;
    const char *p=buf+1; unsigned long major,minor,micro;
    if (number(&p,63,&major,'.') || number(&p,63,&minor,'.') || number(&p,15,&micro,'\0')) return -1;
    SkaterUpdate r={0}; snprintf(r.version,sizeof(r.version),"%lu.%lu.%lu",major,minor,micro);
    r.title_version=(uint16_t)((major<<10)|(minor<<4)|micro); *out=r; return 0;
}

int skater_update_parse(const char *text,size_t size,SkaterUpdate *out) {
    if (!text || !out || !size || size>SKATER_UPDATE_MAX_MANIFEST || memchr(text,0,size)) return -1;
    char buf[SKATER_UPDATE_MAX_MANIFEST+1];
    unsigned long major,minor,micro,bytes;
    SkaterUpdate result={0};
    memcpy(buf,text,size); buf[size]=0;
    const char *p=buf;
    const char prefix[]="SKATER-UPDATE-1\n";
    if (strncmp(p,prefix,sizeof(prefix)-1)) return -1;
    p+=sizeof(prefix)-1;
    if (number(&p,63,&major,'.') || number(&p,63,&minor,'.') || number(&p,15,&micro,'\n')) return -1;
    for (unsigned i=0;i<2;i++) {
        const char *label=i ? "3dsx " : "cia "; size_t len=strlen(label);
        if (strncmp(p,label,len)) return -1;
        p+=len;
        if (number(&p,SKATER_UPDATE_MAX_FILE,&bytes,' ') || !bytes || strlen(p)<65) return -1;
        result.size[i]=bytes;
        for (unsigned j=0;j<32;j++) {
            int a=hex((unsigned char)*p++),b=hex((unsigned char)*p++);
            if (a<0 || b<0) return -1;
            result.sha256[i][j]=(uint8_t)((a<<4)|b);
        }
        if (*p++!='\n') return -1;
    }
    if (*p) return -1;
    snprintf(result.version,sizeof(result.version),"%lu.%lu.%lu",major,minor,micro);
    result.title_version=(uint16_t)((major<<10)|(minor<<4)|micro);
    *out=result; return 0;
}
