"""ARM11 AES/GHASH vectors with independent references; no Nintendo inputs needed."""
from pathlib import Path
import argparse,hashlib,struct
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM
from unicorn.arm_const import *
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from build_certificate_bridge import elf_sections,elf_symbol

ROOT=Path(__file__).resolve().parents[1]
BASE,RO,DATA,BSS,RAM,STACK,STOP=0x1000000,0x2000000,0x2800000,0x3000000,0x4000000,0x6000000,0x7000000
word=lambda b,p:struct.unpack_from('<I',b,p)[0]
def engine(cro=None):
    uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);uc.ctl_set_cpu_model(UC_CPU_ARM_11MPCORE)
    elf=(ROOT/'payload/aes-gcm-arm.elf').read_bytes();sec=elf_sections(elf)
    if cro:
        st=word(cro,0xc8);bases={0:BASE,1:RO,2:DATA,3:BSS}
        for i in range(4):
            off,size,kind=struct.unpack_from('<III',cro,st+12*i)
            uc.mem_map(bases[i],(size+4095)&~4095)
            if kind!=3:uc.mem_write(bases[i],cro[off:off+size])
        for i in range(word(cro,0x12c)):
            p=word(cro,0x128)+12*i;tag,typ,seg,_,_,value=struct.unpack_from('<IBBBBI',cro,p)
            if typ==2 and tag&15 in bases and seg in bases:
                uc.mem_write(bases[tag&15]+(tag>>4),struct.pack('<I',bases[seg]+value))
        aes,gmult=BASE+0x458f9,BASE+0x94f21
        key=BASE+elf_symbol(elf,sec,'private_AES_set_encrypt_key')
    else:
        included=[s for s in sec.values() if s['flags']&2 and s['size']]
        size=max(s['addr']+s['size'] for s in included)
        text=bytearray(size)
        for s in included:
            if s['type']!=8:text[s['addr']:s['addr']+s['size']]=elf[s['off']:s['off']+s['size']]
        for name in ('.rel.text','.rel.rodata','.rel.data'):
            if name not in sec:continue
            s=sec[name]
            for p in range(s['off'],s['off']+s['size'],8):
                target,info=struct.unpack_from('<II',elf,p)
                if info&255==2:struct.pack_into('<I',text,target,BASE+word(text,target))
        uc.mem_map(BASE,(size+4095)&~4095);uc.mem_write(BASE,bytes(text))
        aes=BASE+elf_symbol(elf,sec,'AES_encrypt')
        gmult=BASE+elf_symbol(elf,sec,'skater_gmult')
        key=BASE+elf_symbol(elf,sec,'private_AES_set_encrypt_key')
    for p,n in [(RAM,0x10000),(STACK,0x10000),(STOP,4096)]:uc.mem_map(p,n)
    return uc,aes,gmult,key

def call(uc,entry,args):
    registers=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]
    saved={r:0xa1000000+i for i,r in enumerate((UC_ARM_REG_R4,UC_ARM_REG_R5,
        UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11))}
    for r,v in [*zip(registers,args),(UC_ARM_REG_SP,STACK+0xff00),(UC_ARM_REG_LR,STOP|1),*saved.items()]:uc.reg_write(r,v)
    uc.emu_start(entry,STOP,count=10000000)
    assert uc.reg_read(UC_ARM_REG_PC)==STOP and uc.reg_read(UC_ARM_REG_SP)==STACK+0xff00
    assert all(uc.reg_read(r)==v for r,v in saved.items())
    return uc.reg_read(UC_ARM_REG_R0)

def gf_multiply(x,h):
    z=0;v=h
    for bit in range(127,-1,-1):
        if x>>bit&1:z^=v
        v=(v>>1)^(0xe1000000000000000000000000000000 if v&1 else 0)
    return z
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cro',type=Path);a=p.parse_args()
    uc,aes,gmult,key_fn=engine(a.cro.read_bytes() if a.cro else None)
    aes_checks=0
    for bits in (128,192,256):
        key=bytes(range(bits//8));uc.mem_write(RAM,key)
        assert call(uc,key_fn,[RAM,bits,RAM+0x1000])==0
        for offset in range(4):
            plain=bytes((i*17+offset)%256 for i in range(16))
            enc=Cipher(algorithms.AES(key),modes.ECB()).encryptor();expected=enc.update(plain)+enc.finalize()
            for in_place in (False,True):
                src=RAM+0x2000+offset;out=src if in_place else RAM+0x3000+offset
                uc.mem_write(src,plain);uc.mem_write(out+16,b'GUARD')
                call(uc,aes,[src,out,RAM+0x1000])
                assert bytes(uc.mem_read(out,16))==expected
                assert bytes(uc.mem_read(out+16,5))==b'GUARD';aes_checks+=1
    for i in range(18):
        h=0 if i==0 else (1<<128)-1 if i==1 else int.from_bytes(hashlib.sha256(('h'+str(i)).encode()).digest()[:16],'big')
        x=int.from_bytes(hashlib.sha256(('x'+str(i)).encode()).digest()[:16],'big')
        basis=[h]
        for j in range(3):basis.append((basis[-1]>>1)^(0xe1000000000000000000000000000000 if basis[-1]&1 else 0))
        table=b''
        for index in range(16):
            v=0
            for j,mask in enumerate((8,4,2,1)):
                if index&mask:v^=basis[j]
            table+=struct.pack('<QQ',v>>64,v&((1<<64)-1))
        uc.mem_write(RAM+0x4000,table);uc.mem_write(RAM+0x5000,x.to_bytes(16,'big')+b'GUARD')
        call(uc,gmult,[RAM+0x5000,RAM+0x4000])
        assert bytes(uc.mem_read(RAM+0x5000,16))==gf_multiply(x,h).to_bytes(16,'big')
        assert bytes(uc.mem_read(RAM+0x5010,5))==b'GUARD'
        assert bytes(uc.mem_read(RAM+0x4000,256))==table
    print('PASS ARM11 AES/GHASH: 24 AES alignment/in-place vectors, 18 independent GF vectors, ABI and canaries')
if __name__=='__main__':main()
