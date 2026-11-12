"""Append ARMv6 AES/GHASH; keep the existing GCM/TLS state machine."""
from pathlib import Path
import hashlib,struct
from build_certificate_bridge import elf_sections,elf_symbol,append_relocations,thumb_bl
from expand_cro_text import transform,rewrite_hashes
from lz11_codec import compress
from decompress_lz11 import decompress

ROOT=Path(__file__).resolve().parents[1]
SOURCE_SHA='D5E92FFA2ADDDDAB86E9577CB3751E359CA5646B93A6D27ED37AA5FB417CCBFE'
FIRST=0x14E7B0
ELF_SHA='C5A7344302711C63EF2E97F707FF64D8E650F962472D799936F1F484C934A81E'
RAW_SHA='EA80E68D35A669D3BC44FEE6F88D4A1CB9C55248AA81C2B1D1125D8A1FA17B4A'
LEX_SHA='0DA1A8231272D7A7F09AD504D8701B7929AA5A4B1C1391500C36D46AC1351B47'
def build(source,elf):
    if hashlib.sha256(source).hexdigest().upper()!=SOURCE_SHA:raise ValueError('Unexpected ECDH-fast CRO')
    sec=elf_sections(elf)
    if sec['.text']['addr']!=FIRST or sec.get('.bss',{}).get('size',0):raise ValueError('Unexpected ARM crypto ELF layout')
    parts=[sec[k] for k in ('.text','.rodata','.data') if k in sec and sec[k]['size']]
    end=max(s['addr']+s['size'] for s in parts);payload=bytearray(end-FIRST)
    for s in parts:
        if s['addr']<FIRST or s['off']+s['size']>len(elf):raise ValueError('Section bounds')
        payload[s['addr']-FIRST:s['addr']-FIRST+s['size']]=elf[s['off']:s['off']+s['size']]
    u=lambda b,p:struct.unpack_from('<I',b,p)[0]
    st=u(source,0xc8);off,size,kind=struct.unpack_from('<III',source,st)
    if (off,size,kind)!=(0x180,FIRST,0):raise ValueError('Unexpected text segment')
    ro=min(struct.unpack_from('<III',source,st+12*i)[0] for i in range(u(source,0xcc)) if struct.unpack_from('<III',source,st+12*i)[2]==1)
    needed=max(0,len(payload)-(ro-off-size))
    # This variant needs one additional code page; all existing function
    # segment-relative addresses stay fixed while metadata file offsets move.
    out,layout=transform(source,max(4096,(needed+4095)&~4095),payload)
    out=bytearray(out)
    records=[];seen=set()
    for name in ('.rel.text','.rel.rodata','.rel.data'):
        if name not in sec:continue
        s=sec[name]
        if s['type']!=9 or s['entsize']!=8:raise ValueError('Relocation format')
        for p in range(s['off'],s['off']+s['size'],8):
            target,info=struct.unpack_from('<II',elf,p)
            if info&255!=2:continue
            if target in seen or not FIRST<=target<end:raise ValueError('Relocation bounds')
            value=u(payload,target-FIRST)
            if not FIRST<=(value&~1)<end:raise ValueError('Unmapped absolute pointer')
            records.append((target,0,value));seen.add(target)
    for site,symbol,expected in [(0x458F8,'AES_encrypt','f0b58c4685b00578'),
                                 (0x94F20,'skater_gmult','84464348f0b58cb0')]:
        actual=source[off+site:off+site+8]
        if actual!=bytes.fromhex(expected):raise ValueError('Unexpected stock entry '+hex(site)+': '+actual.hex())
        entry=elf_symbol(elf,sec,symbol)
        if not FIRST<=entry<end:raise ValueError('Missing ARM entry')
        # Both APIs have <=3 arguments, so caller-saved r3 is free. BX switches
        # from Thumb to ARM without changing the original return address.
        out[off+site:off+site+8]=bytes.fromhex('004b1847')+struct.pack('<I',entry)
        records.append((site+4,0,entry))
    out=append_relocations(out,records,0);rewrite_hashes(out);out[:128]=source[:128]
    return bytes(out),dict(payload_bytes=len(payload),new_relocations=len(records),inserted_bytes=layout['new_file_size']-len(source))

def main():
    source=(ROOT/'build/oss-skaterplus.cro').read_bytes();elf=(ROOT/'payload/aes-gcm-arm.elf').read_bytes()
    if hashlib.sha256(elf).hexdigest().upper()!=ELF_SHA:raise ValueError('ELF hash mismatch')
    raw,info=build(source,elf);packed=compress(raw)
    if decompress(packed)!=raw:raise ValueError('LZ11 round trip')
    if hashlib.sha256(raw).hexdigest().upper()!=RAW_SHA or hashlib.sha256(packed).hexdigest().upper()!=LEX_SHA:raise ValueError('Output hash mismatch')
    (ROOT/'build/oss-aes-arm.cro').write_bytes(raw);(ROOT/'build/oss-aes-arm.cro.lex').write_bytes(packed)
    (ROOT/'build/oss-skaterplus.cro').write_bytes(raw);(ROOT/'build/oss-skaterplus.cro.lex').write_bytes(packed)
    print(info)
if __name__=='__main__':main()
