"""Append ARM11 arithmetic to the verified certificate-fast CRO.

Keeps the existing TLS hooks/handshake checks and redirects only payload_ecdh.
Complete module outputs remain local; the ELF contains project/micro-ecc code.
"""
from pathlib import Path
import hashlib,struct
from build_certificate_bridge import (elf_sections,elf_symbol,append_relocations,
    rewrite_hashes,thumb_bl)
from lz11_codec import compress
from decompress_lz11 import decompress

ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='0EBEC4B34E28179B70AEA23EB361DEE3760F82C1482CB3F14DBE6B6960048ADA'
ELF_SHA='43249E4CB44F046DAE67B2E9BCD6F2D5BF5D6946FD15672DCB13C6F79EE66629'
RAW_SHA='D5E92FFA2ADDDDAB86E9577CB3751E359CA5646B93A6D27ED37AA5FB417CCBFE'
LEX_SHA='D5417762E5BA427A5A90FF7FA48A54D3418BF40B94EC941D2016C84B54EC8965'
FIRST=0x14CF98
OLD_ENTRY=0x145AC8

def build(source,elf):
    if hashlib.sha256(elf).hexdigest().upper()!=ELF_SHA:
        raise ValueError('Unexpected ECDH ELF')
    if hashlib.sha256(source).hexdigest().upper()!=SOURCE_SHA:
        raise ValueError('Expected the verified certificate-fast CRO')
    sec=elf_sections(elf)
    parts=[sec[k] for k in ('.text','.rodata','.data') if k in sec and sec[k]['size']]
    if sec['.text']['addr']!=FIRST:raise ValueError('Wrong ELF link address')
    end=max(s['addr']+s['size'] for s in parts)
    image=bytearray(end-FIRST)
    for s in parts:
        if s['addr']<FIRST or s['off']+s['size']>len(elf):raise ValueError('ELF section bounds')
        image[s['addr']-FIRST:s['addr']-FIRST+s['size']]=elf[s['off']:s['off']+s['size']]
    word=lambda data,p:struct.unpack_from('<I',data,p)[0]
    st=word(source,0xc8)
    text_start,text_size,kind=struct.unpack_from('<III',source,st)
    if (text_start,text_size,kind)!=(0x180,FIRST,0):raise ValueError('Unexpected text segment')
    ro_start=min(struct.unpack_from('<III',source,st+12*i)[0]
        for i in range(word(source,0xcc)) if struct.unpack_from('<III',source,st+12*i)[2]==1)
    if text_start+end>ro_start or any(source[text_start+FIRST:text_start+end]):
        raise ValueError('Payload does not fit empty executable padding')
    bss=sec.get('.bss',dict(addr=0,size=0))
    if bss['size']>16:raise ValueError('Unexpected ECDH BSS')
    records=[];seen=set();old_bss=word(source,0x94)
    for name in ('.rel.text','.rel.rodata','.rel.data'):
        if name not in sec:continue
        s=sec[name]
        if s['type']!=9 or s['entsize']!=8:raise ValueError('Relocation format')
        for p in range(s['off'],s['off']+s['size'],8):
            target,info=struct.unpack_from('<II',elf,p)
            if info&255!=2:continue
            if target in seen or not FIRST<=target<end:raise ValueError('Relocation target')
            seen.add(target);value=word(image,target-FIRST)
            if bss['size'] and bss['addr']<=value<bss['addr']+bss['size']:
                records.append((target,3,old_bss+value-bss['addr']))
            elif FIRST<=(value&~1)<end:records.append((target,0,value))
            else:raise ValueError('Unmapped absolute ELF pointer')
    # GNU ld may synthesize absolute ARM->Thumb veneers after ELF relocations.
    pattern=bytes.fromhex('00c09fe51cff2fe1')
    pos=0
    while (pos:=image.find(pattern,pos))!=-1:
        target=FIRST+pos+8;value=word(image,pos+8)
        if target in seen or not value&1 or not FIRST<=(value&~1)<end:
            raise ValueError('Unexpected interworking veneer')
        seen.add(target);records.append((target,0,value));pos+=12
    out=bytearray(source)
    out[text_start+FIRST:text_start+end]=image
    struct.pack_into('<I',out,st+4,end)
    entry=elf_symbol(elf,sec,'payload_ecdh')
    old=bytes.fromhex('f7b5170004000191')
    if out[text_start+OLD_ENTRY:text_start+OLD_ENTRY+8]!=old:raise ValueError('Old wrapper changed')
    out[text_start+OLD_ENTRY:text_start+OLD_ENTRY+8]=bytes.fromhex('10b5')+thumb_bl(OLD_ENTRY+2,entry)+bytes.fromhex('10bd')
    out=append_relocations(out,records,bss['size'])
    rewrite_hashes(out);out[:128]=source[:128]
    return bytes(out),dict(entry=entry,payload_bytes=len(image),relocations=len(records),bss_bytes=bss['size'])

def main():
    source=(ROOT/'build/oss-skaterplus.cro').read_bytes()
    elf=(ROOT/'payload/ecdh-arm.elf').read_bytes()
    raw,info=build(source,elf)
    packed=compress(raw)
    if decompress(packed)!=raw:raise AssertionError('LZ11 round trip')
    if hashlib.sha256(raw).hexdigest().upper()!=RAW_SHA or hashlib.sha256(packed).hexdigest().upper()!=LEX_SHA:
        raise AssertionError('Output hash mismatch')
    (ROOT/'build/oss-ecdh-arm.cro').write_bytes(raw)
    (ROOT/'build/oss-ecdh-arm.cro.lex').write_bytes(packed)
    (ROOT/'build/oss-skaterplus.cro').write_bytes(raw)
    (ROOT/'build/oss-skaterplus.cro.lex').write_bytes(packed)
    print(info)
    print('raw_sha256='+hashlib.sha256(raw).hexdigest().upper())
    print('lex_sha256='+hashlib.sha256(packed).hexdigest().upper())
    print('elf_sha256='+hashlib.sha256(elf).hexdigest().upper())
if __name__=='__main__':main()
