"""Verify real ARM11 ECDH arithmetic and the redirected Thumb ABI entry.

The default tests the distributable ELF; --cro tests a locally built module.
No crypto calls are stubbed. Results are compared with Python/OpenSSL.
"""
from pathlib import Path
import argparse,hashlib,json,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM
from unicorn.arm_const import (UC_CPU_ARM_11MPCORE,UC_ARM_REG_R0,UC_ARM_REG_R1,
    UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,
    UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,
    UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from build_certificate_bridge import elf_sections,elf_symbol

ROOT=Path(__file__).resolve().parents[1]
BASE,BSS,RAM,STACK,STOP=0x1000000,0x3000000,0x4000000,0x6000000,0x7000000
FIRST,OLD_ENTRY=0x14CF98,0x145AC8
ORDER=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
word=lambda b,p:struct.unpack_from('<I',b,p)[0]

def image(elf,cro):
    sections=elf_sections(elf)
    if cro is not None:
        st=word(cro,0xc8);off,size,kind=struct.unpack_from('<III',cro,st)
        assert off==0x180 and kind==0
        text=bytearray(cro[off:off+size])
        for i in range(word(cro,0x12c)):
            p=word(cro,0x128)+i*12
            target,typ,seg=struct.unpack_from('<IBB',cro,p)
            if target&15 or target>>4<FIRST:continue
            assert typ==2 and seg in (0,3)
            struct.pack_into('<I',text,target>>4,{0:BASE,3:BSS}[seg]+word(cro,p+8))
        return bytes(text),OLD_ENTRY
    included=[sections[k] for k in ('.text','.rodata','.data') if k in sections]
    text=bytearray(max(s['addr']+s['size'] for s in included))
    for s in included:text[s['addr']:s['addr']+s['size']]=elf[s['off']:s['off']+s['size']]
    bss=sections.get('.bss',dict(addr=0,size=0))
    for name in ('.rel.text','.rel.rodata','.rel.data'):
        if name not in sections:continue
        s=sections[name]
        for p in range(s['off'],s['off']+s['size'],8):
            target,info=struct.unpack_from('<II',elf,p)
            if info&255!=2:continue
            value=word(text,target)
            value=BSS+value-bss['addr'] if bss['addr']<=value<bss['addr']+bss['size'] else BASE+value
            struct.pack_into('<I',text,target,value)
    return bytes(text),elf_symbol(elf,sections,'payload_ecdh')

def run(text,entry,a,b,expected_success=True):
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);uc.ctl_set_cpu_model(UC_CPU_ARM_11MPCORE)
    for address,size in [(BASE,(len(text)+4095)&~4095),(BSS,0x20000),
        (RAM,0x10000),(STACK,0x10000),(STOP,4096)]:uc.mem_map(address,size)
    uc.mem_write(BASE,text)
    peer=ec.derive_private_key(b,ec.SECP256R1())
    public=lambda key:key.public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)[1:]
    uc.mem_write(RAM,a.to_bytes(32,'big'));uc.mem_write(RAM+0x100,public(peer))
    # Canaries detect output overruns; no caller-saved arguments are mocked.
    uc.mem_write(RAM+0x1fc,b'ABCD'+bytes(64)+b'EFGH')
    uc.mem_write(RAM+0x2fc,b'IJKL'+bytes(32)+b'MNOP')
    saved={r:0xa1000000+i for i,r in enumerate((UC_ARM_REG_R4,UC_ARM_REG_R5,
        UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11))}
    for r,v in [(UC_ARM_REG_R0,RAM),(UC_ARM_REG_R1,RAM+0x100),
        (UC_ARM_REG_R2,RAM+0x200),(UC_ARM_REG_R3,RAM+0x300),
        (UC_ARM_REG_SP,STACK+0xff00),(UC_ARM_REG_LR,STOP|1),*saved.items()]:uc.reg_write(r,v)
    uc.emu_start((BASE+entry)|1,STOP,count=300000000)
    assert uc.reg_read(UC_ARM_REG_PC)==STOP and uc.reg_read(UC_ARM_REG_R0)==int(expected_success)
    assert uc.reg_read(UC_ARM_REG_SP)==STACK+0xff00
    assert all(uc.reg_read(r)==v for r,v in saved.items())
    for p,v in [(RAM+0x1fc,b'ABCD'),(RAM+0x240,b'EFGH'),(RAM+0x2fc,b'IJKL'),(RAM+0x320,b'MNOP')]:
        assert bytes(uc.mem_read(p,4))==v
    if expected_success:
        client=ec.derive_private_key(a,ec.SECP256R1())
        assert bytes(uc.mem_read(RAM+0x200,64))==public(client)
        assert bytes(uc.mem_read(RAM+0x300,32))==client.exchange(ec.ECDH(),peer.public_key())

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cro',type=Path);a=p.parse_args()
    elf=(ROOT/'payload/ecdh-arm.elf').read_bytes()
    text,entry=image(elf,a.cro.read_bytes() if a.cro else None)
    vectors=[(7,11),(2,3),(3,5),(19,7)]+[
        (int.from_bytes(hashlib.sha256(('client'+str(i)).encode()).digest(),'big')%(ORDER-1)+1,
         int.from_bytes(hashlib.sha256(('server'+str(i)).encode()).digest(),'big')%(ORDER-1)+1) for i in range(8)]
    for client,peer in vectors:run(text,entry,client,peer)
    # Existing micro-ecc returns failure for these valid edge scalars. Keep
    # that behavior: the TLS hook retries rather than using a wrong secret.
    for client in (0,ORDER,ORDER+1,1,ORDER-1,ORDER-2):run(text,entry,client,3,False)
    print('PASS ARM11 ECDH: 12 independent vectors, 6 rejection/retry cases, ABI and output canaries')
if __name__=='__main__':main()
