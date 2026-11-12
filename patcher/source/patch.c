#include "patch.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }

int lz11_decompress(const uint8_t *in, size_t in_size, uint8_t **outp, size_t *out_size) {
    if (in_size<4 || in[0]!=0x11) return -1;
    size_t wanted=le32(in)&0xffffff00u; wanted>>=8; size_t pos=4;
    if (!wanted) { if (in_size<8) return -1; wanted=le32(in+4); pos=8; }
    uint8_t *out=malloc(wanted); if (!out) return -2; size_t at=0;
    while (at<wanted) {
        if (pos>=in_size) goto invalid;
        uint8_t flags=in[pos++];
        for (int bit=7;bit>=0 && at<wanted;bit--) {
            if (!(flags&(1u<<bit))) { if (pos>=in_size) goto invalid; out[at++]=in[pos++]; continue; }
            if (pos>=in_size) goto invalid;
            uint8_t first=in[pos++]; unsigned indicator=first>>4; size_t length,disp;
            if (indicator==0) {
                if (pos+2>in_size) goto invalid;
                uint8_t second=in[pos++],third=in[pos++];
                length=(((first&15u)<<4)|(second>>4))+0x11; disp=(((second&15u)<<8)|third)+1;
            } else if (indicator==1) {
                if (pos+3>in_size) goto invalid;
                uint8_t second=in[pos++],third=in[pos++],fourth=in[pos++];
                length=(((first&15u)<<12)|((unsigned)second<<4)|(third>>4))+0x111; disp=(((third&15u)<<8)|fourth)+1;
            } else {
                if (pos>=in_size) goto invalid;
                uint8_t second=in[pos++]; length=indicator+1; disp=(((first&15u)<<8)|second)+1;
            }
            if (disp>at) goto invalid;
            while (length-- && at<wanted) { out[at]=out[at-disp]; at++; }
        }
    }
    *outp=out; *out_size=wanted; return 0;
invalid: free(out); return -1;
}

int lz11_pack_literals(const uint8_t *data, size_t size, uint8_t **packed, size_t *packed_size) {
    if (size>0xffffff) return -1;
    const size_t header_size=size ? 4 : 8;
    const size_t total=header_size+size+(size+7)/8;
    uint8_t *out=malloc(total);
    if (!out) return -2;
    const uint8_t header[8]={0x11,(uint8_t)size,(uint8_t)(size>>8),(uint8_t)(size>>16)};
    memcpy(out,header,header_size);
    size_t used=header_size;
    for (size_t pos=0;pos<size;) {
        size_t take=size-pos;
        if (take>8) take=8;
        out[used++]=0;
        memcpy(out+used,data+pos,take);
        used+=take;
        pos+=take;
    }
    *packed=out;
    *packed_size=total;
    return 0;
}

int delta_apply(const uint8_t *p, size_t n, const uint8_t *source, size_t source_size,
                uint8_t **targetp, size_t *target_size) {
    if (n<80 || memcmp(p,"SKD1",4)) return -1;
    uint32_t expected_source=le32(p+4), wanted=le32(p+8), count=le32(p+12);
    uint8_t hash[32]; if (expected_source!=source_size) return -1;
    sha256_buffer(source,source_size,hash); if (memcmp(hash,p+16,32)) return -1;
    uint8_t *target=malloc(wanted); if (!target) return -2;
    size_t ip=80,op=0;
    for (uint32_t i=0;i<count;i++) {
        if (ip+5>n) goto invalid;
        uint8_t kind=p[ip++]; uint32_t length=le32(p+ip); ip+=4;
        if ((size_t)length>wanted-op) goto invalid;
        if (kind==0) {
            if (ip+4>n) goto invalid;
            uint32_t off=le32(p+ip); ip+=4;
            if ((size_t)off>source_size || (size_t)length>source_size-off) goto invalid;
            memcpy(target+op,source+off,length);
        } else if (kind==1) {
            if ((size_t)length>n-ip) goto invalid;
            memcpy(target+op,p+ip,length); ip+=length;
        } else goto invalid;
        op+=length;
    }
    if (op!=wanted || ip!=n) goto invalid;
    sha256_buffer(target,wanted,hash); if (memcmp(hash,p+48,32)) goto invalid;
    *targetp=target; *target_size=wanted; return 0;
invalid: free(target); return -1;
}
