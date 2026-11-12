"""Integrate P-256/P-384 certificate verification with the TLS CRO.

Builds the local test module without SD/FTP writes. Refuses
unexpected ELF, CRO, hook bytes, absolute pointers, or structure changes.
"""
from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from expand_cro_text import rewrite_hashes, transform
from build_ecdhe_static_patch import thumb_bl
from lz11_codec import compress
from decompress_lz11 import decompress

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "build" / "oss-tls12.cro"
BASE_LEX = ROOT / "build" / "oss-tls12.cro.lex"
EC_MODE = True
ELF = ROOT / "payload" / "certificate-bridge" / "ec_bridge.elf"
OUT = ROOT / "build" / "oss-skaterplus.cro"
OUT_LEX = ROOT / "build" / "oss-skaterplus.cro.lex"
EXPECTED_LEX = "48A5882C7A31B1365160468808695587DC58AF977F7AEDD08A8B115772D3BC9A"
EXPECTED_ELF = "0A089C9275394D81BC62661951560ADE9EEB368E6973AAE7CFBD5DAA560492C1"
EXPECTED_RAW = "0EBEC4B34E28179B70AEA23EB361DEE3760F82C1482CB3F14DBE6B6960048ADA"
EXPECTED_OUTPUT_LEX = "D48122075C2F5996F77421842C24AD710FB3C99B7C2697CFBFDFCC9FB36384C7"


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def elf_sections(blob: bytes) -> dict[str, dict[str, int]]:
    if blob[:4] != b"\x7fELF" or blob[4:6] != b"\x01\x01":
        raise ValueError("expected ELF32 little-endian")
    shoff, shentsize, shnum, shstrndx = (
        u32(blob, 32), struct.unpack_from("<H", blob, 46)[0],
        struct.unpack_from("<H", blob, 48)[0],
        struct.unpack_from("<H", blob, 50)[0],
    )
    if shentsize != 40 or shnum > 128 or shoff + shnum * shentsize > len(blob):
        raise ValueError("invalid ELF section table")
    raw = [struct.unpack_from("<10I", blob, shoff + i * shentsize)
           for i in range(shnum)]
    names = raw[shstrndx]
    string_table = blob[names[4]:names[4] + names[5]]
    result: dict[str, dict[str, int]] = {}
    for i, fields in enumerate(raw):
        end = string_table.find(b"\0", fields[0])
        name = string_table[fields[0]:end].decode("ascii")
        result[name] = dict(index=i, type=fields[1], flags=fields[2],
                            addr=fields[3], off=fields[4], size=fields[5],
                            link=fields[6], info=fields[7], entsize=fields[9])
    return result


def elf_symbol(blob: bytes, sections: dict[str, dict[str, int]], name: str) -> int:
    syms, names = sections[".symtab"], sections[".strtab"]
    table = blob[names["off"]:names["off"] + names["size"]]
    for pos in range(syms["off"], syms["off"] + syms["size"], 16):
        string, value = struct.unpack_from("<II", blob, pos)
        end = table.find(b"\0", string)
        if end < 0:
            raise ValueError("invalid ELF symbol string")
        if table[string:end].decode("ascii") == name:
            return value & ~1
    raise ValueError(f"missing ELF symbol {name}")


def replace_exact(cro: bytearray, rel: int, old: bytes, new: bytes) -> None:
    if len(old) != len(new) or cro[rel + 0x180:rel + 0x180 + len(old)] != old:
        raise ValueError(f"unexpected patch site 0x{rel:X}")
    cro[rel + 0x180:rel + 0x180 + len(old)] = new


def repair_browser_thumb_veneers(image: bytearray, first: int, elf: bytes,
                                  sections: dict[str, dict[str, int]]) -> list[tuple[int, int, int]]:
    """Replace ld's incorrect Thumb->ARM transitions to stock Thumb code.

    Absolute --defsym symbols lack STT_FUNC/Thumb metadata. Each old veneer
    executes BX PC then an ARM B to a Thumb function. Keep its eight-byte
    footprint and route it through a literal-based Thumb trampoline instead.
    PUSH {r4,lr}; BL trampoline; POP {r4,pc} preserves all four arguments,
    the original r4/LR, and 8-byte AAPCS stack alignment. The trampoline's
    LDR r4,[pc]; BX r4 uses an explicitly odd, CRO-relocated target address.
    """
    targets = {
        "browser_md_ctx_init": 0x97B21,
        "browser_md_ctx_copy": 0xA3431,
        "browser_md_final": 0xAAEF9,
        "browser_md_ctx_cleanup": 0x97AAD,
        "browser_verify_final": 0x5780D,
    }
    records = []
    for name, target in targets.items():
        veneer = elf_symbol(elf, sections, "__" + name + "_from_thumb")
        pos = veneer - first
        old = bytes(image[pos:pos + 8])
        if len(old) != 8 or old[:4] != bytes.fromhex("7847FDE7"):
            raise ValueError(f"unexpected stock-call veneer for {name}")
        arm_branch = u32(old, 4)
        if arm_branch >> 24 != 0xEA:
            raise ValueError(f"expected an unconditional ARM branch for {name}")
        displacement = (arm_branch & 0xFFFFFF) << 2
        if displacement & (1 << 25):
            displacement -= 1 << 26
        if veneer + 12 + displacement != (target & ~1):
            raise ValueError(f"wrong stock-call veneer destination for {name}")
        if (first + len(image)) & 3:
            raise ValueError("Thumb trampoline literal is not word aligned")
        trampoline = first + len(image)
        image.extend(bytes.fromhex("004C2047") + struct.pack("<I", target))
        image[pos:pos + 8] = (bytes.fromhex("10B5") +
                              thumb_bl(veneer + 2, trampoline) + bytes.fromhex("10BD"))
        records.append((trampoline + 4, 0, target))
    return records


def retarget_method_table(cro: bytearray, table_rel: int) -> None:
    off, count = u32(cro, 0x128), u32(cro, 0x12C)
    matches = [off + i * 12 for i in range(count)
               if u32(cro, off + i * 12) == (0x57384 << 4)]
    if len(matches) != 1:
        raise ValueError("ASN.1 method-table relocation not unique")
    pos = matches[0]
    if cro[pos + 4] != 2 or cro[pos + 5] != 2 or u32(cro, pos + 8) != 0x84:
        raise ValueError("unexpected ASN.1 method-table relocation")
    cro[pos + 5] = 0  # new table is in the expanded text segment
    struct.pack_into("<I", cro, pos + 8, table_rel)


def append_relocations(cro: bytearray, records: list[tuple[int, int, int]],
                       bss_growth: int) -> bytearray:
    reloc_off, count = u32(cro, 0x128), u32(cro, 0x12C)
    insertion = reloc_off + count * 12
    if not 0 < insertion <= len(cro):
        raise ValueError("invalid CRO internal relocation table")
    encoded = bytearray()
    for output, segment, addend in records:
        if output >= 1 << 28 or segment not in (0, 1, 3):
            raise ValueError("invalid relocation target")
        encoded += struct.pack("<IBBBBI", output << 4, 2, segment, 0, 0, addend)
    old = bytes(cro)
    result = bytearray(old[:insertion] + encoded + old[insertion:])
    shift = len(encoded)
    for field in (0x84, 0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0,
                  0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118,
                  0x120, 0x128, 0x130):
        value = u32(old, field)
        if value >= insertion and value:
            struct.pack_into("<I", result, field, value + shift)
    struct.pack_into("<I", result, 0x90, len(result))
    struct.pack_into("<I", result, 0x12C, count + len(records))
    segment_off, segment_count = u32(result, 0xC8), u32(result, 0xCC)
    if segment_count != 5:
        raise ValueError("unexpected CRO segment count")
    for i in range(segment_count):
        p = segment_off + 12 * i
        file_offset, size, kind = struct.unpack_from("<III", result, p)
        if kind == 3:
            struct.pack_into("<I", result, p + 4, size + bss_growth)
        elif file_offset >= insertion and file_offset:
            struct.pack_into("<I", result, p, file_offset + shift)
    struct.pack_into("<I", result, 0x94, u32(old, 0x94) + bss_growth)
    return result


def main() -> None:
    if sys.argv[1:]:
        raise SystemExit("usage: build_certificate_bridge.py")
    source = BASE.read_bytes()
    packed = BASE_LEX.read_bytes()
    if hashlib.sha256(packed).hexdigest().upper() != EXPECTED_LEX or decompress(packed) != source:
        raise ValueError("working baseline does not match recorded live package")
    elf = ELF.read_bytes()
    if hashlib.sha256(elf).hexdigest().upper() != EXPECTED_ELF:
        raise ValueError("certificate bridge ELF hash mismatch")
    sections = elf_sections(elf)
    first = sections[".text"]["addr"]
    bss = sections.get(".bss", {"addr": 0, "size": 0})
    if first != 0x146B00 or bss["size"] > 0x100:
        raise ValueError("ELF is linked for the wrong CRO image")
    included = [sections[name] for name in (".text", ".rodata", ".data") if name in sections]
    image_end = max(s["addr"] + s["size"] for s in included)
    image = bytearray(image_end - first)
    for s in included:
        if s["off"] + s["size"] > len(elf):
            raise ValueError("truncated ELF section")
        pos = s["addr"] - first
        image[pos:pos + s["size"]] = elf[s["off"]:s["off"] + s["size"]]
    stock_call_relocations = []
    if EC_MODE:
        stock_call_relocations = repair_browser_thumb_veneers(image, first, elf, sections)
        image_end = first + len(image)

    segment_start = u32(source, 0xB0)
    segment_off, count = u32(source, 0xC8), u32(source, 0xCC)
    if count != 5:
        raise ValueError("unexpected source CRO segments")
    text_file, text_size, text_kind = struct.unpack_from("<III", source, segment_off)
    if text_kind != 0 or text_file != segment_start:
        raise ValueError("unexpected source CRO text segment")
    old_end = text_file + text_size
    gap = first - text_size
    if not 0 <= gap <= 32:
        raise ValueError("ELF base does not follow existing text")
    extra = b""
    table_rel = None
    if EC_MODE:
        table_rel = (image_end + 3) & ~3
        if table_rel - first + 24 > 0x8000:
            raise ValueError("EC method table does not fit expanded text")
        extra = b"\0" * (table_rel - image_end) + b"\0" * 24
    candidate, layout = transform(source, 0x8000 if EC_MODE else 0x6000,
                                  b"\0" * gap + image + extra)
    candidate = bytearray(candidate)
    if layout["payload_segment_offset"] + gap != first:
        raise AssertionError("payload segment offset mismatch")

    # Nintendo's X509_verify_cert does not invoke ctx->verify. Intercept the
    # issuer-key decode in its real certificate-signature loop instead.
    call_file = 0x1E4B8 + 0x180
    old_call = source[call_file:call_file + 4]
    if old_call != bytes.fromhex("9BF056FB"):
        raise ValueError(f"unexpected X509_get_pubkey call: {old_call.hex()}")
    candidate[call_file:call_file + 4] = thumb_bl(0x1E4B8, first)

    if EC_MODE:
        assert table_rel is not None
        method = elf_symbol(elf, sections, "ec_asn1_method")
        cert_hook = elf_symbol(elf, sections, "ec_cert_type_hook")
        ske_hook = elf_symbol(elf, sections, "ec_tls_verify_final")
        if not first <= method < image_end or not first <= cert_hook < image_end or not first <= ske_hook < image_end:
            raise ValueError("EC bridge symbol outside ELF image")
        replace_exact(candidate, 0x57324, bytes.fromhex("0522"), bytes.fromhex("0622"))
        # Keep the mutable app_methods global at 0x57358 intact. The stock
        # bsearch uses that same literal plus four for its five static entries;
        # redirect only its LDR to the separate table literal at 0x57384.
        replace_exact(candidate, 0x57322, bytes.fromhex("0D49"), bytes.fromhex("1849"))
        # ARM11 MPCore implements ARMv6K/Thumb-1. Use MOV r8,r8 for NOP;
        # the Thumb-2 hint encoding BF00 is not an ARMv6K instruction.
        replace_exact(candidate, 0x57328, bytes.fromhex("091D"), bytes.fromhex("C046"))
        replace_exact(candidate, 0x5736A, bytes.fromhex("0528"), bytes.fromhex("0628"))
        replace_exact(candidate, 0x57376, bytes.fromhex("411F"), bytes.fromhex("811F"))
        replace_exact(candidate, 0x97770, bytes.fromhex("884202D0"),
                      thumb_bl(0x97770, cert_hook))
        replace_exact(candidate, 0xBC222, bytes.fromhex("9BF7F3FA"),
                      thumb_bl(0xBC222, ske_hook))
        retarget_method_table(candidate, table_rel)

    old_bss = u32(source, 0x94)
    records: list[tuple[int, int, int]] = list(stock_call_relocations)
    seen: set[int] = set()
    for name in (".rel.text", ".rel.rodata", ".rel.data"):
        section = sections.get(name)
        if not section:
            continue
        if section["type"] != 9 or section["entsize"] != 8:
            raise ValueError(f"unexpected {name} format")
        count = section["size"] // 8
        for i in range(count):
            out, info = struct.unpack_from("<II", elf, section["off"] + i * 8)
            if info & 0xFF != 2:  # Only absolute pointers need CRO relocation.
                continue
            if out in seen or not first <= out < image_end:
                raise ValueError("duplicate or out-of-range absolute pointer")
            seen.add(out)
            value = u32(image, out - first)
            if bss["size"] and bss["addr"] <= value < bss["addr"] + bss["size"]:
                records.append((out, 3, old_bss + value - bss["addr"]))
            elif 0 <= value < image_end:
                records.append((out, 0, value))
            else:
                raise ValueError(f"unmapped absolute target 0x{value:X} at 0x{out:X}")
    if EC_MODE:
        assert table_rel is not None
        # EVP_PKEY_asn1_find expects a sorted array of method pointers.
        # Preserve all five existing methods and insert EC (NID 408).
        entries = [(1, 0x18528), (1, 0x18594), (1, 0xB6D8),
                   (0, method), (1, 0xD1CC), (1, 0xA134)]
        for index, (segment, addend) in enumerate(entries):
            out = table_rel + index * 4
            if out in seen:
                raise ValueError("duplicate EC method table relocation")
            records.append((out, segment, addend))
    # GNU ld emits interworking veneers after relocation processing. Their
    # absolute target literals do not appear in ELF .rel.text, but the CRO
    # loader must still rebase them. Refuse any unexpected shape or count.
    veneer_pattern = bytes.fromhex("00C09FE51CFF2FE1")  # ldr ip,[pc]; bx ip
    veneer_offsets = []
    start = 0
    while (pos := image.find(veneer_pattern, start)) != -1:
        veneer_offsets.append(pos)
        start = pos + len(veneer_pattern)
    if len(veneer_offsets) > 1:
        raise ValueError(f"unexpected ARM-to-Thumb veneer count {len(veneer_offsets)}")
    if veneer_offsets:
        veneer_output = first + veneer_offsets[0] + len(veneer_pattern)
        veneer_target = u32(image, veneer_output - first)
        if veneer_output in seen or not first <= (veneer_target & ~1) < image_end or not (veneer_target & 1):
            raise ValueError("invalid ARM-to-Thumb veneer target")
        records.append((veneer_output, 0, veneer_target))
    candidate = append_relocations(candidate, records, bss["size"])
    rewrite_hashes(candidate)
    candidate[:0x80] = source[:0x80]  # preserve CRR-listed identity
    if u32(candidate, 0x90) != len(candidate):
        raise AssertionError("CRO file length mismatch")
    raw_hash = hashlib.sha256(candidate).hexdigest().upper()
    if raw_hash != EXPECTED_RAW:
        raise AssertionError(f"final CRO hash mismatch: {raw_hash}")
    OUT.write_bytes(candidate)
    output_packed = compress(candidate)
    if decompress(output_packed) != candidate:
        raise AssertionError("LZ11 round-trip failed")
    packed_hash = hashlib.sha256(output_packed).hexdigest().upper()
    if packed_hash != EXPECTED_OUTPUT_LEX:
        raise AssertionError(f"final compressed CRO hash mismatch: {packed_hash}")
    OUT_LEX.write_bytes(output_packed)
    print(f"offline_candidate={OUT}")
    print(f"sha256={raw_hash}")
    print(f"text_end=0x{layout['payload_segment_offset'] + gap + len(image):X}")
    print(f"new_relocations={len(records)} bss_growth={bss['size']}")
    print(f"lex_sha256={packed_hash}")


if __name__ == "__main__":
    main()
