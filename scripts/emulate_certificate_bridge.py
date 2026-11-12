#!/usr/bin/env python3
"""Exercise the integrated ARM11 issuer-key hook with real ECDSA signatures.

Requires cryptography and unicorn. Generated certificates/keys are test-only;
only the browser allocator and the original fallback are stubbed.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_CPU_ARM_11MPCORE, UC_ARM_REG_CPSR,
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4, UC_ARM_REG_R5,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
from build_certificate_bridge import elf_sections, elf_symbol

ROOT = Path(__file__).resolve().parents[1]
BASE, RAM, STACK, STOP, BSS = 0x1000000, 0x4000000, 0x6000000, 0x7000000, 0x2500000

def run(cro, elf, cert, issuer_key, mutation=None):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_11MPCORE)
    if cro is None:
        # CI can exercise the redistributable ELF without Nintendo files.
        sections=elf_sections(elf)
        included=[s for name,s in sections.items() if name in ('.text','.rodata','.data')]
        text=bytearray(max(s['addr']+s['size'] for s in included))
        for s in included:text[s['addr']:s['addr']+s['size']]=elf[s['off']:s['off']+s['size']]
        for name in ('.rel.text','.rel.rodata','.rel.data'):
            if name not in sections:continue
            s=sections[name]
            for pos in range(s['off'],s['off']+s['size'],8):
                target,info=struct.unpack_from('<II',elf,pos)
                if info&255==2:
                    value=struct.unpack_from('<I',text,target)[0]
                    struct.pack_into('<I',text,target,BASE+value)
    else:
        word = lambda off: struct.unpack_from('<I', cro, off)[0]
        text = bytearray(cro[0x180:0x180 + word(0x184)])
        for i in range(word(0x12c)):
            pos = word(0x128) + i * 12
            out, kind, seg = struct.unpack_from('<IBB', cro, pos)
            target = out >> 4
            if target < 0x146b00:
                continue
            assert out & 15 == 0 and kind == 2 and seg in (0, 1, 3)
            address = {0: BASE, 1: 0x2000000, 3: BSS}[seg]
            struct.pack_into('<I', text, target, address + word(pos + 8))
    for address, size in [(BASE, (len(text)+4095)&~4095), (RAM, 0x2000000),
                          (STACK, 0x10000), (STOP, 4096), (BSS, 0x20000)]:
        uc.mem_map(address, size)
    uc.mem_write(BASE, bytes(text))
    cursor = RAM + 0x1000
    def put(data):
        nonlocal cursor
        result = (cursor + 7) & ~7
        cursor = result + max(len(data), 8)
        assert cursor < RAM + 0x2000000
        uc.mem_write(result, data)
        return result
    def blank(n): return put(bytes(n))
    def setword(p, off, value): uc.mem_write(p+off, struct.pack('<I', value))
    def oid(data):
        p=blank(24); setword(p,12,len(data));setword(p,16,put(data));return p
    def alg(obj, param=0): return put(struct.pack('<II',obj,param))
    def string(data):
        p=blank(16);setword(p,0,len(data));setword(p,8,put(data));return p
    def name(data):
        p=blank(20);setword(p,12,put(data));setword(p,16,len(data));return p

    bits=issuer_key.curve.key_size
    point=issuer_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if mutation=='wrong-key':
        point=ec.generate_private_key(issuer_key.curve).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    tbs=cert.tbs_certificate_bytes
    sig=cert.signature
    if mutation=='signature': sig=sig[:-1]+bytes([sig[-1]^1])
    if mutation=='tbs': tbs=tbs[:-1]+bytes([tbs[-1]^1])
    digest={256:2,384:3,512:4}[cert.signature_hash_algorithm.digest_size*8]
    signature_oid=bytes.fromhex('2a8648ce3d0403')+bytes([digest])
    outer=alg(oid(signature_oid), blank(8) if mutation=='parameters' else 0)
    inner=alg(oid(signature_oid if mutation!='algorithm' else bytes.fromhex('2a8648ce3d040302' if digest!=2 else '2a8648ce3d040303')))
    if mutation=='unknown': outer=alg(oid(bytes.fromhex('2a8648ce3d040301')))
    curve=oid(bytes.fromhex('2a8648ce3d030107' if bits==256 else '2b81040022'))
    parameter=put(struct.pack('<II',6,curve))
    pub=blank(12);setword(pub,0,alg(oid(bytes.fromhex('2a8648ce3d0201')),parameter));setword(pub,4,string(point))
    si,ii=blank(52),blank(52)
    setword(si,8,inner);setword(si,12,name(b'issuer'))
    setword(si,40,put(tbs));setword(si,44,len(tbs))
    if mutation=='modified':setword(si,48,1)
    setword(ii,20,name(b'other' if mutation=='issuer' else b'issuer'));setword(ii,24,pub)
    subject=put(struct.pack('<III',si,outer,string(sig)));issuer=put(struct.pack('<III',ii,0,0))
    subject_entry=put(struct.pack('<I',subject));issuer_entry=put(struct.pack('<I',issuer))
    reached={'verified':False,'fallback':False,'stopped':False}
    def alloc(engine,*_):
        assert engine.reg_read(UC_ARM_REG_CPSR)&0x20
        n=engine.reg_read(UC_ARM_REG_R0)
        engine.reg_write(UC_ARM_REG_R0,blank(n) if n<0x100000 else 0)
        engine.reg_write(UC_ARM_REG_PC,engine.reg_read(UC_ARM_REG_LR))
    def free(engine,*_):engine.reg_write(UC_ARM_REG_PC,engine.reg_read(UC_ARM_REG_LR))
    def fallback(engine,*_):
        reached['fallback']=True;engine.reg_write(UC_ARM_REG_R0,0)
        engine.reg_write(UC_ARM_REG_PC,engine.reg_read(UC_ARM_REG_LR))
    def verified(engine,*_):reached['verified']=True;engine.emu_stop()
    def stop(engine,*_):reached['stopped']=True;engine.emu_stop()
    for address,func in [(BASE+0xbb48c,alloc),(BASE+0xbb458,free),
        (BASE+0xb9b68,fallback),(BASE+0x1e4ee,verified),(STOP,stop)]:
        uc.hook_add(UC_HOOK_CODE,func,begin=address,end=address)
    uc.reg_write(UC_ARM_REG_R0,issuer);uc.reg_write(UC_ARM_REG_R4,subject_entry)
    uc.reg_write(UC_ARM_REG_R5,issuer_entry);uc.reg_write(UC_ARM_REG_SP,STACK+0xf000)
    uc.reg_write(UC_ARM_REG_LR,STOP|1)
    entry=elf_symbol(elf,elf_sections(elf),'p384_hook_thumb')
    uc.emu_start((BASE+entry)|1,STOP+4,count=1_500_000_000)
    assert reached['verified'] or reached['stopped'], 'instruction budget exhausted'
    assert reached['verified']==(mutation is None), (bits,digest,mutation,reached)
    assert uc.reg_read(UC_ARM_REG_SP)==STACK+0xf000
    assert uc.reg_read(UC_ARM_REG_R4)==subject_entry and uc.reg_read(UC_ARM_REG_R5)==issuer_entry

def main():
    if sys.argv[1:] not in ([],['--elf-only']):raise SystemExit('usage: emulate_certificate_bridge.py [--elf-only]')
    cro=None if sys.argv[1:] else (ROOT/'build/oss-skaterplus.cro').read_bytes()
    elf=(ROOT/'payload/certificate-bridge/ec_bridge.elf').read_bytes()
    for curve in [ec.SECP256R1(),ec.SECP384R1()]:
        key=ec.generate_private_key(curve)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'test only')])
        for hash_type in [hashes.SHA256,hashes.SHA384,hashes.SHA512]:
            now=datetime.now(timezone.utc)
            cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
                  .public_key(key.public_key()).serial_number(1)
                  .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
                  .sign(key,hash_type()))
            for mutation in [None,'signature','tbs','wrong-key','algorithm','parameters','unknown','issuer','modified']:
                run(cro,elf,cert,key.public_key(),mutation)
            print(f'PASS ARM11 {curve.name}/{hash_type.name}: valid + 8 rejection cases',flush=True)
    fixtures=ROOT/'backups/tiktok-certificates'
    if fixtures.is_dir():
        for i in (0,1):
            cert=x509.load_pem_x509_certificate((fixtures/f'www.tiktok.com-{i}.pem').read_bytes())
            issuer=x509.load_pem_x509_certificate((fixtures/f'www.tiktok.com-{i+1}.pem').read_bytes())
            run(cro,elf,cert,issuer.public_key())
            run(cro,elf,cert,issuer.public_key(),'signature')
            print(f'PASS captured TikTok chain pair {i}: valid + tampered',flush=True)

if __name__=='__main__':main()
