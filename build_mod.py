#!/usr/bin/env python3
"""Quiet Lands - Walk peacefully through the Lands Between.

Creates a custom talisman called "Grace Given Freely" that grants:
  - Full invisibility (enemies can't see or hear you)
  - Massive damage (one-shot everything)
  - Full invulnerability (zero damage taken, no fall damage, noDead)

Enemies still fight each other — they just can't see you.
Equip/unequip the talisman to toggle the effect.

Pipeline:
  1. regulation.bin: decrypt → decompress → patch SpEffect + Accessory + CharaInit → recompress → re-encrypt
  2. item.msgbnd.dcx: extract from BHD/BDT → decompress KRAK → patch FMG text → recompress → write as loose file
"""
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import argparse
import ctypes
import os
import struct
import zstandard

GAME_DIR = Path("/home/ve/.steam/debian-installation/steamapps/common/ELDEN RING/Game")
REGULATION = GAME_DIR / "regulation.bin"
PROJECT_DIR = Path(__file__).parent
OUTPUT_DIR = PROJECT_DIR / "mod"
OUTPUT_REG = OUTPUT_DIR / "regulation.bin"
OUTPUT_MSG = OUTPUT_DIR / "msg" / "engus" / "item_dlc02.msgbnd.dcx"
WORK_DIR = PROJECT_DIR / "work"

# Keys are loaded at runtime from files specified via CLI args or env vars.
# See parse_args() and load_keys().
ER_KEY: bytes = b""

# === Custom talisman: "Grace Given Freely" ===
TALISMAN_NAME = "Grace Given Freely"
TALISMAN_SUMMARY = "A talisman bathed in gold, humming with quiet Grace.\nRenders the wearer unseen and unassailable."
TALISMAN_DESCRIPTION = (
    "A talisman suffused with the warm light of Grace,\n"
    "of the kind that once guided the Tarnished.\n"
    "\n"
    "Enemies cannot perceive the wearer at all,\n"
    "and all harm slides away like rain from gold leaf.\n"
    "\n"
    "Grace, it seems, was never meant to guide\n"
    "the Tarnished toward battle —\n"
    "only toward the beauty that waited beyond it."
)

# Custom accessory row 204000, with a new SpEffect based on
# Crimson Amber Medallion's known-working passive structure.
CUSTOM_ACCESSORY_ID = 204000
SOURCE_ACCESSORY_ID = 6010       # Concealing Veil (template for item appearance)
SPEFFECT_ID = 204000             # SpEffect: invisibility + damage + invulnerability
TEMPLATE_SPEFFECT_ID = 310000    # Crimson Amber Medallion (known-working passive)

# SpEffect field offsets (from Smithbox ER paramdef, verified against binary)
SPEFF_SIGHT_ENEMY_RATE = 0xFC
SPEFF_HEAR_ENEMY_RATE = 0x100
SPEFF_ATK_RATES = {
    'physicsAttackPowerRate': 0x48,
    'magicAttackPowerRate':   0x4C,
    'fireAttackPowerRate':    0x50,
    'thunderAttackPowerRate': 0x54,
    'darkAttackPowerRate':    0x1E0,
    'slashAttackPowerRate':   0x220,
    'blowAttackPowerRate':    0x224,
    'thrustAttackPowerRate':  0x228,
    'neutralAttackPowerRate': 0x22C,
}
DAMAGE_MULTIPLIER = 999.0
SPEFF_DMG_CUT_RATES = {
    'slashDamageCutRate':     0x1C,
    'blowDamageCutRate':      0x20,
    'thrustDamageCutRate':    0x24,
    'neutralDamageCutRate':   0x28,
    'magicDamageCutRate':     0x2C,
    'fireDamageCutRate':      0x30,
    'thunderDamageCutRate':   0x34,
    'darkDamageCutRate':      0x1D0,
    'toughnessDamageCutRate': 0x1B4,
}
SPEFF_FALL_DAMAGE_RATE = 0xDC
SPEFF_NO_DEAD_BYTE = 0x162
# Status effect immunity bits (1 = immune)
SPEFF_STATUS_IMMUNITY = [
    (0x163, 2, 'Poison'),
    (0x163, 3, 'Scarlet Rot'),
    (0x163, 4, 'Hemorrhage'),
    (0x163, 5, 'Death Blight'),
    (0x259, 3, 'Frostbite'),
    (0x15F, 7, 'Sleep'),
    (0x160, 0, 'Madness'),
]
# EquipParamAccessory field offsets (96-byte rows in ER)
ACC_REF_ID = 4          # s32: triggered SpEffect reference (conditional, not passive)
ACC_WEIGHT = 12         # f32: weight
ACC_SORT_ID = 28        # s32: sort order
ACC_ICON_ID = 38        # u16: icon
ACC_ACC_GROUP = 72      # s16: accessory group (mutual exclusion)
ACC_RESIDENT_SPEFFECT1 = 76  # s32: passive always-on SpEffect while equipped

# CharaInitParam
CHARA_EQUIP_ACCESSORY01 = 0x40
STARTING_CLASSES = [10] + list(range(3000, 3010))  # 10=tutorial + 3000-3009=classes

DATA0_RSA_KEY: str = ""


# ============================================================
# Regulation.bin helpers
# ============================================================

def decrypt_regulation(data: bytes) -> bytes:
    iv = data[:16]
    ct = data[16:]
    if len(ct) % 16:
        ct += b'\x00' * (16 - len(ct) % 16)
    plaintext = AES.new(ER_KEY, AES.MODE_CBC, iv).decrypt(ct)
    try:
        plaintext = unpad(plaintext, 16)
    except ValueError:
        pass
    return plaintext


def encrypt_regulation(data: bytes) -> bytes:
    iv = b'\x00' * 16
    # Zero-pad to AES block size (game uses zero-padding, not PKCS7)
    if len(data) % 16:
        data = data + b'\x00' * (16 - len(data) % 16)
    ct = AES.new(ER_KEY, AES.MODE_CBC, iv).encrypt(data)
    return iv + ct


def decompress_dcx(data: bytes) -> tuple[bytes, bytes]:
    assert data[:4] == b'DCX\x00', "Not DCX"
    dcs_off = struct.unpack_from('>I', data, 0x08)[0]
    dcp_off = struct.unpack_from('>I', data, 0x0C)[0]
    uncomp_size = struct.unpack_from('>I', data, dcs_off + 4)[0]
    comp_size = struct.unpack_from('>I', data, dcs_off + 8)[0]
    method = data[dcp_off + 4:dcp_off + 8]

    dca_off = dcp_off + 0x20
    while data[dca_off:dca_off + 4] != b'DCA\x00':
        dca_off += 4
    comp_data_off = dca_off + 8
    compressed = data[comp_data_off:comp_data_off + comp_size]

    if method == b'ZSTD':
        decompressed = zstandard.ZstdDecompressor().decompress(
            compressed, max_output_size=uncomp_size + 0x10000)
    elif method == b'KRAK':
        decompressed = oodle_decompress(compressed, uncomp_size)
    else:
        raise ValueError(f"Unsupported DCX: {method}")

    return decompressed, data[:comp_data_off]


def compress_dcx(decompressed: bytes, header: bytes) -> bytes:
    method = header[header.find(b'DCP\x00') + 4:header.find(b'DCP\x00') + 8]
    if method == b'ZSTD':
        return compress_dcx_zstd(decompressed)
    elif method == b'KRAK':
        compressed = oodle_compress(decompressed)
        header = bytearray(header)
        dcs_off = struct.unpack_from('>I', header, 0x08)[0]
        struct.pack_into('>I', header, dcs_off + 4, len(decompressed))
        struct.pack_into('>I', header, dcs_off + 8, len(compressed))
        return bytes(header) + compressed
    else:
        raise ValueError(f"Unsupported DCX compression: {method}")


def compress_dcx_zstd(decompressed: bytes) -> bytes:
    """Build DCX_ZSTD from scratch, matching SoulsFormats format exactly."""
    params = zstandard.ZstdCompressionParameters.from_level(
        21, window_log=16, write_content_size=0)
    compressed = zstandard.ZstdCompressor(compression_params=params).compress(decompressed)

    dcx = bytearray()
    dcx += struct.pack('>4s', b'DCX\x00')
    dcx += struct.pack('>I', 0x11000)
    dcx += struct.pack('>I', 0x18)       # DCS offset
    dcx += struct.pack('>I', 0x24)       # DCP offset
    dcx += struct.pack('>I', 0x44)
    dcx += struct.pack('>I', 0x4C)
    dcx += struct.pack('>4s', b'DCS\x00')
    dcx += struct.pack('>I', len(decompressed))
    dcx += struct.pack('>I', len(compressed))
    dcx += struct.pack('>4s', b'DCP\x00')
    dcx += struct.pack('>4s', b'ZSTD')
    dcx += struct.pack('>I', 0x20)
    dcx += struct.pack('>BBBB', 21, 0, 0, 0)
    dcx += struct.pack('>III', 0, 0, 0)
    dcx += struct.pack('>I', 0x10100)
    dcx += struct.pack('>4s', b'DCA\x00')
    dcx += struct.pack('>I', 8)
    dcx += compressed
    # Pad to 16-byte alignment
    while len(dcx) % 16:
        dcx.append(0)
    return bytes(dcx)


# ============================================================
# Oodle (Kraken) compression via linoodle
# ============================================================

_oodle_lib = None

def _load_oodle():
    global _oodle_lib
    if _oodle_lib is not None:
        return _oodle_lib
    _oodle_lib = ctypes.CDLL(str(PROJECT_DIR / "liblinoodle.so"))

    _oodle_lib.OodleLZ_Decompress.restype = ctypes.c_size_t
    _oodle_lib.OodleLZ_Decompress.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_int,
    ]

    _oodle_lib.OodleLZ_Compress.restype = ctypes.c_size_t
    _oodle_lib.OodleLZ_Compress.argtypes = [
        ctypes.c_int64,    # codec (Kraken=8)
        ctypes.c_void_p, ctypes.c_size_t,   # srcBuf, srcLen
        ctypes.c_void_p,   # dstBuf
        ctypes.c_int64,    # level (Optimal2=6)
        ctypes.c_void_p,   # opts
        ctypes.c_size_t,   # offs
        ctypes.c_size_t,   # unused
        ctypes.c_void_p,   # scratch
        ctypes.c_size_t,   # scratchSize
    ]
    return _oodle_lib


def oodle_decompress(compressed: bytes, uncomp_size: int) -> bytes:
    lib = _load_oodle()
    src = (ctypes.c_uint8 * len(compressed))(*compressed)
    dst = (ctypes.c_uint8 * uncomp_size)()
    result = lib.OodleLZ_Decompress(
        src, len(compressed), dst, uncomp_size,
        0, 0, 0, None, 0, None, None, None, 0, 0)
    if result != uncomp_size:
        raise RuntimeError(f"Oodle decompress failed: got {result}, expected {uncomp_size}")
    return bytes(dst)


def oodle_compress(data: bytes) -> bytes:
    lib = _load_oodle()
    src = (ctypes.c_uint8 * len(data))(*data)
    # Kraken=8, Optimal2=6; output buffer needs extra space
    max_comp = len(data) + 65536
    dst = (ctypes.c_uint8 * max_comp)()
    result = lib.OodleLZ_Compress(
        8,                  # codec: Kraken
        src, len(data),     # source
        dst,                # dest
        6,                  # level: Optimal2
        None,               # opts
        0, 0,               # offs, unused
        None, 0,            # scratch, scratchSize
    )
    if result <= 0:
        raise RuntimeError(f"Oodle compress failed: {result}")
    return bytes(dst[:result])


# ============================================================
# BND4 / param helpers
# ============================================================

def parse_bnd4_entries(data: bytes):
    assert data[:4] == b'BND4'
    file_count = struct.unpack_from('<I', data, 0x0C)[0]
    entry_size = struct.unpack_from('<I', data, 0x20)[0]

    entries = []
    for i in range(file_count):
        off = 0x40 + i * entry_size
        comp_size = struct.unpack_from('<q', data, off + 8)[0]
        data_offset = struct.unpack_from('<I', data, off + 24)[0]
        name_offset = struct.unpack_from('<I', data, off + 32)[0]

        nb = data[name_offset:name_offset + 500]
        name = ""
        for j in range(0, len(nb) - 1, 2):
            if nb[j] == 0 and nb[j + 1] == 0:
                name = nb[:j].decode('utf-16-le', errors='replace')
                break

        entries.append((name, data_offset, comp_size))

    return entries


def parse_param_rows(data: bytes) -> list:
    row_count = struct.unpack_from('<H', data, 0x0A)[0]
    flags1 = data[0x2D]
    long_offsets = bool(flags1 & 0x04)

    header_size = 12 + 32 + 4
    if long_offsets:
        header_size += 16
    elif flags1 & 0x03:
        header_size += 16

    if long_offsets:
        rows = []
        for i in range(row_count):
            off = header_size + i * 24
            rid = struct.unpack_from('<i', data, off)[0]
            rdata = struct.unpack_from('<q', data, off + 8)[0]
            rname = struct.unpack_from('<q', data, off + 16)[0]
            rows.append((rid, rdata, rname))
        return rows
    else:
        rows = []
        for i in range(row_count):
            off = header_size + i * 12
            rid = struct.unpack_from('<I', data, off)[0]
            rdata = struct.unpack_from('<I', data, off + 4)[0]
            rname = struct.unpack_from('<I', data, off + 8)[0]
            rows.append((rid, rdata, rname))
        return rows


def find_param_entry(entries, suffix):
    for name, doff, dsize in entries:
        if name.endswith(suffix):
            return name, doff, dsize
    return None


# ============================================================
# BHD/BDT extraction
# ============================================================

def bhd_path_hash(path: str) -> int:
    h = 0
    for c in path:
        h = (ord(c) + 133 * h) & 0xFFFFFFFFFFFFFFFF
    return h


def rsa_decrypt_bhd(bhd_path: Path, key_pem: str) -> bytes:
    key = RSA.import_key(key_pem)
    n, e = key.n, key.e
    input_block = (key.size_in_bits() + 7) // 8
    output_block = input_block - 1

    encrypted = bhd_path.read_bytes()
    result = bytearray()
    for i in range(0, len(encrypted), input_block):
        block = encrypted[i:i + input_block]
        if len(block) < input_block:
            block += b'\x00' * (input_block - len(block))
        ct_int = int.from_bytes(block, 'big')
        pt_int = pow(ct_int, e, n)
        result.extend(pt_int.to_bytes(output_block, 'big'))
    return bytes(result)


def extract_from_bhd(target_path: str) -> bytes:
    """Extract a file from Data0.bhd/Data0.bdt by virtual path."""
    target_hash = bhd_path_hash(target_path)
    bhd_file = GAME_DIR / "Data0.bhd"
    bdt_file = GAME_DIR / "Data0.bdt"

    decrypted = rsa_decrypt_bhd(bhd_file, DATA0_RSA_KEY)

    # Parse BHD5 header
    magic = struct.unpack_from('<I', decrypted, 0)[0]
    assert magic == 0x35444842, f"Bad BHD5 magic: 0x{magic:08X}"
    bucket_count = struct.unpack_from('<i', decrypted, 16)[0]
    bucket_offset = struct.unpack_from('<i', decrypted, 20)[0]

    # Search buckets for our hash
    pos = bucket_offset
    for i in range(bucket_count):
        entry_count = struct.unpack_from('<i', decrypted, pos)[0]
        entry_offset = struct.unpack_from('<i', decrypted, pos + 4)[0]
        pos += 8

        for j in range(entry_count):
            epos = entry_offset + j * 40
            name_hash = struct.unpack_from('<Q', decrypted, epos)[0]
            if name_hash != target_hash:
                continue

            padded_size = struct.unpack_from('<i', decrypted, epos + 8)[0]
            size = struct.unpack_from('<i', decrypted, epos + 12)[0]
            offset = struct.unpack_from('<q', decrypted, epos + 16)[0]
            aes_offset = struct.unpack_from('<q', decrypted, epos + 32)[0]

            actual_size = size if size > 0 else padded_size
            raw = bytearray(bdt_file.read_bytes()[offset:offset + padded_size])

            if aes_offset != 0:
                aes_key = decrypted[aes_offset:aes_offset + 16]
                range_count = struct.unpack_from('<i', decrypted, aes_offset + 16)[0]
                for k in range(range_count):
                    roff = aes_offset + 20 + k * 16
                    r_start = struct.unpack_from('<q', decrypted, roff)[0]
                    r_end = struct.unpack_from('<q', decrypted, roff + 8)[0]
                    if r_start != -1 and r_end != -1 and r_start != r_end:
                        length = r_end - r_start
                        cipher = AES.new(aes_key, AES.MODE_ECB)
                        raw[r_start:r_start + length] = cipher.decrypt(bytes(raw[r_start:r_start + length]))

            return bytes(raw[:actual_size])

    raise FileNotFoundError(f"Not found in Data0: {target_path}")


# ============================================================
# FMG reading/writing (V2 format, ER)
# ============================================================

def parse_fmg(data: bytes) -> dict[int, str]:
    """Parse FMG V2, return {id: text}."""
    HEADER_SIZE = 40
    range_count = struct.unpack_from('<I', data, 12)[0]
    string_count = struct.unpack_from('<I', data, 16)[0]
    str_offsets_offset = struct.unpack_from('<Q', data, 24)[0]

    ranges = []
    for i in range(range_count):
        roff = HEADER_SIZE + i * 16
        first_idx, first_id, last_id = struct.unpack_from('<iii', data, roff)
        ranges.append((first_idx, first_id, last_id))

    str_offsets = []
    for i in range(string_count):
        off = struct.unpack_from('<Q', data, str_offsets_offset + i * 8)[0]
        str_offsets.append(off)

    entries = {}
    for first_idx, first_id, last_id in ranges:
        for j, string_id in enumerate(range(first_id, last_id + 1)):
            idx = first_idx + j
            if idx >= len(str_offsets):
                break
            soff = str_offsets[idx]
            if soff == 0:
                entries[string_id] = ''
            else:
                end = soff
                while end + 1 < len(data) and not (data[end] == 0 and data[end + 1] == 0):
                    end += 2
                entries[string_id] = data[soff:end].decode('utf-16-le', errors='replace')

    return entries


def build_fmg(entries: dict[int, str]) -> bytes:
    """Build FMG V2 binary from {id: text}."""
    sorted_ids = sorted(entries.keys())

    # Build ranges of contiguous IDs
    ranges = []
    range_start_idx = first_id = last_id = None
    for string_idx, sid in enumerate(sorted_ids):
        if first_id is None:
            range_start_idx = string_idx
            first_id = last_id = sid
        elif sid == last_id + 1:
            last_id = sid
        else:
            ranges.append((range_start_idx, first_id, last_id))
            range_start_idx = string_idx
            first_id = last_id = sid
    if first_id is not None:
        ranges.append((range_start_idx, first_id, last_id))

    string_count = len(sorted_ids)
    range_count = len(ranges)

    HEADER_SIZE = 40
    ranges_size = range_count * 16
    str_offsets_offset = HEADER_SIZE + ranges_size
    str_offsets_size = string_count * 8
    str_data_offset = str_offsets_offset + str_offsets_size

    # Encode all strings as UTF-16LE + null terminator
    encoded_strings = []
    for sid in sorted_ids:
        text = entries[sid]
        if text:
            encoded_strings.append(text.encode('utf-16-le') + b'\x00\x00')
        else:
            encoded_strings.append(b'')

    # Calculate string offsets
    str_offsets = []
    current_off = str_data_offset
    for enc in encoded_strings:
        if enc:
            str_offsets.append(current_off)
            current_off += len(enc)
        else:
            str_offsets.append(0)

    file_size = current_off

    # Build binary
    out = bytearray(file_size)

    # Header (40 bytes)
    out[1] = 0       # big_endian = false
    out[2] = 2       # version = 2
    struct.pack_into('<I', out, 4, file_size)
    out[8] = 1       # one
    out[9] = 0       # zero
    struct.pack_into('<I', out, 12, range_count)
    struct.pack_into('<I', out, 16, string_count)
    struct.pack_into('<I', out, 20, 255)   # unk2 = 0xFF
    struct.pack_into('<Q', out, 24, str_offsets_offset)
    # bytes 32-39 = pad (already zeroed)

    # Ranges
    for i, (first_idx, first_id, last_id) in enumerate(ranges):
        roff = HEADER_SIZE + i * 16
        struct.pack_into('<iii', out, roff, first_idx, first_id, last_id)
        # 4 bytes pad (already zeroed)

    # String offsets
    for i, soff in enumerate(str_offsets):
        struct.pack_into('<Q', out, str_offsets_offset + i * 8, soff)

    # String data
    for i, enc in enumerate(encoded_strings):
        if enc:
            off = str_offsets[i]
            out[off:off + len(enc)] = enc

    return bytes(out)


# ============================================================
# BND4 modification helpers
# ============================================================

def replace_bnd4_entry(bnd4_data: bytearray, entries: list, entry_idx: int, new_data: bytes) -> bytearray:
    """Replace a BND4 entry's data in-place. If sizes differ, rebuild the whole BND4."""
    name, old_off, old_size = entries[entry_idx]
    if len(new_data) == old_size:
        bnd4_data[old_off:old_off + old_size] = new_data
        return bnd4_data

    # Need to rebuild: collect all entries with their data
    file_count = struct.unpack_from('<I', bnd4_data, 0x0C)[0]
    entry_header_size = struct.unpack_from('<I', bnd4_data, 0x20)[0]

    all_entries = []
    for i in range(file_count):
        eoff = 0x40 + i * entry_header_size
        e_size = struct.unpack_from('<q', bnd4_data, eoff + 8)[0]
        e_data_off = struct.unpack_from('<I', bnd4_data, eoff + 24)[0]
        e_name_off = struct.unpack_from('<I', bnd4_data, eoff + 32)[0]

        if i == entry_idx:
            all_entries.append((eoff, new_data, e_name_off))
        else:
            all_entries.append((eoff, bytes(bnd4_data[e_data_off:e_data_off + e_size]), e_name_off))

    # Find where name strings start (after all entry headers)
    names_start = 0x40 + file_count * entry_header_size

    # Read all name strings
    name_strings = []
    for _, _, noff in all_entries:
        nb = bnd4_data[noff:noff + 500]
        end = 0
        for j in range(0, len(nb) - 1, 2):
            if nb[j] == 0 and nb[j + 1] == 0:
                end = j + 2
                break
        name_strings.append(bytes(bnd4_data[noff:noff + end]))

    # Rebuild: headers + names + data
    # Keep original header (0x40 bytes) and entry header structures
    new_bnd4 = bytearray(bnd4_data[:0x40 + file_count * entry_header_size])

    # Write names
    name_offsets = []
    for ns in name_strings:
        name_offsets.append(len(new_bnd4))
        new_bnd4.extend(ns)

    # Align to 16 bytes before data
    while len(new_bnd4) % 16:
        new_bnd4.append(0)

    # Write data
    data_offsets = []
    for _, edata, _ in all_entries:
        data_offsets.append(len(new_bnd4))
        new_bnd4.extend(edata)
        # Align each entry
        while len(new_bnd4) % 16:
            new_bnd4.append(0)

    # Update entry headers
    for i in range(file_count):
        eoff = 0x40 + i * entry_header_size
        _, edata, _ = all_entries[i]
        struct.pack_into('<q', new_bnd4, eoff + 8, len(edata))      # size
        struct.pack_into('<I', new_bnd4, eoff + 24, data_offsets[i]) # data offset
        struct.pack_into('<I', new_bnd4, eoff + 32, name_offsets[i]) # name offset

    return new_bnd4


# ============================================================
# Main build pipeline
# ============================================================

def build_regulation():
    """Build modded regulation.bin."""
    print(f"Loading: {REGULATION}")
    raw = REGULATION.read_bytes()

    print("Decrypting...")
    decrypted = decrypt_regulation(raw)

    print("Decompressing DCX...")
    bnd4_data, dcx_header = decompress_dcx(decrypted)
    bnd4_data = bytearray(bnd4_data)
    entries = parse_bnd4_entries(bnd4_data)
    print(f"  BND4: {len(bnd4_data):,} bytes, {len(entries)} entries")

    # === Patch 1: SpEffect — create custom SpEffect based on Crimson Amber Medallion ===
    # Copy the known-working passive structure from SpEffect 310000, then apply our buffs.
    # We avoid modifying SpEffect 360100 (Concealing Veil) which has conditional trigger behavior.
    sp_entry = find_param_entry(entries, 'SpEffectParam.param')
    assert sp_entry, "SpEffectParam not found!"
    sp_name, sp_off, sp_size = sp_entry
    sp_rows = parse_param_rows(bnd4_data[sp_off:sp_off + sp_size])
    sp_row_size = sp_rows[1][1] - sp_rows[0][1]
    print(f"\n  SpEffectParam: {len(sp_rows)} rows (row_size={sp_row_size})")

    template_roff = target_roff = None
    for rid, roff, _ in sp_rows:
        if rid == TEMPLATE_SPEFFECT_ID:
            template_roff = roff
        if rid == SPEFFECT_ID:
            target_roff = roff

    assert template_roff is not None, f"Template SpEffect {TEMPLATE_SPEFFECT_ID} not found"
    assert target_roff is not None, f"Target SpEffect {SPEFFECT_ID} not found"

    # Copy Crimson Amber Medallion's known-working passive structure
    src = sp_off + template_roff
    dst = sp_off + target_roff
    bnd4_data[dst:dst + sp_row_size] = bnd4_data[src:src + sp_row_size]
    print(f"    Copied SpEffect {TEMPLATE_SPEFFECT_ID} -> {SPEFFECT_ID}")
    print(f"    Modifying SpEffect {SPEFFECT_ID}:")

    # Invisibility — regular enemies can't see or hear the player
    struct.pack_into('<f', bnd4_data, dst + SPEFF_SIGHT_ENEMY_RATE, 0.0)
    print(f"      sightSearchEnemyRate -> 0.0")
    struct.pack_into('<f', bnd4_data, dst + SPEFF_HEAR_ENEMY_RATE, 0.0)
    print(f"      hearingSearchEnemyRate -> 0.0")

    # 999x damage
    for name, field_off in SPEFF_ATK_RATES.items():
        struct.pack_into('<f', bnd4_data, dst + field_off, DAMAGE_MULTIPLIER)
        print(f"      {name} -> {DAMAGE_MULTIPLIER}")

    # Full invulnerability
    for name, field_off in SPEFF_DMG_CUT_RATES.items():
        struct.pack_into('<f', bnd4_data, dst + field_off, 0.0)
        print(f"      {name} -> 0.0")

    struct.pack_into('<f', bnd4_data, dst + SPEFF_FALL_DAMAGE_RATE, 0.0)
    print(f"      fallDamageRate -> 0.0")

    bnd4_data[dst + SPEFF_NO_DEAD_BYTE] = bnd4_data[dst + SPEFF_NO_DEAD_BYTE] | 0x01
    print(f"      noDead: bit 0 set")

    # Status effect immunity
    for byte_off, bit, name in SPEFF_STATUS_IMMUNITY:
        bnd4_data[dst + byte_off] = bnd4_data[dst + byte_off] | (1 << bit)
        print(f"      disable{name}: set")

    # Clear template HP boost
    struct.pack_into('<f', bnd4_data, dst + 0x10, 1.0)

    # === Patch 2: EquipParamAccessory — create custom talisman from Concealing Veil template ===
    acc_entry = find_param_entry(entries, 'EquipParamAccessory.param')
    assert acc_entry, "EquipParamAccessory not found!"
    acc_name, acc_off, acc_size = acc_entry
    acc_rows = parse_param_rows(bnd4_data[acc_off:acc_off + acc_size])
    row_size = acc_rows[1][1] - acc_rows[0][1]
    print(f"\n  EquipParamAccessory: {len(acc_rows)} rows (row_size={row_size})")

    src_roff = dst_roff = None
    for rid, roff, _ in acc_rows:
        if rid == SOURCE_ACCESSORY_ID:
            src_roff = roff
        elif rid == CUSTOM_ACCESSORY_ID:
            dst_roff = roff

    assert src_roff is not None, f"Source accessory {SOURCE_ACCESSORY_ID} not found"
    assert dst_roff is not None, f"Target accessory {CUSTOM_ACCESSORY_ID} not found"

    # Copy Concealing Veil's row data into our custom slot
    src_abs = acc_off + src_roff
    dst_abs = acc_off + dst_roff
    bnd4_data[dst_abs:dst_abs + row_size] = bnd4_data[src_abs:src_abs + row_size]
    print(f"    Copied row {SOURCE_ACCESSORY_ID} -> {CUSTOM_ACCESSORY_ID}")

    # Set a unique accessoryGroup so it doesn't conflict with the original
    struct.pack_into('<h', bnd4_data, dst_abs + ACC_ACC_GROUP, CUSTOM_ACCESSORY_ID & 0x7FFF)
    print(f"    accessoryGroup = {CUSTOM_ACCESSORY_ID & 0x7FFF}")

    # Point refId to our custom SpEffect (not Concealing Veil's conditional one)
    struct.pack_into('<i', bnd4_data, dst_abs + ACC_REF_ID, SPEFFECT_ID)
    print(f"    refId = {SPEFFECT_ID}")

    # residentSpEffectId1: invisibility + damage + invulnerability
    struct.pack_into('<i', bnd4_data, dst_abs + ACC_RESIDENT_SPEFFECT1, SPEFFECT_ID)
    print(f"    residentSpEffectId1 = {SPEFFECT_ID}")

    # === Patch 3: CharaInitParam — equip custom talisman on all starting classes ===
    ci_entry = find_param_entry(entries, 'CharaInitParam.param')
    assert ci_entry, "CharaInitParam not found!"
    ci_name, ci_off, ci_size = ci_entry
    ci_rows = parse_param_rows(bnd4_data[ci_off:ci_off + ci_size])
    print(f"\n  CharaInitParam: {len(ci_rows)} rows")

    classes_patched = 0
    for rid, roff, _ in ci_rows:
        if rid in STARTING_CLASSES:
            abs_acc = ci_off + roff + CHARA_EQUIP_ACCESSORY01
            old_acc = struct.unpack_from('<i', bnd4_data, abs_acc)[0]
            struct.pack_into('<i', bnd4_data, abs_acc, CUSTOM_ACCESSORY_ID)
            print(f"    Class {rid}: accessory01 = {old_acc} -> {CUSTOM_ACCESSORY_ID}")
            classes_patched += 1
    print(f"    Patched {classes_patched} starting classes")

    # NpcParam boss neutralization removed in v1.1 — setting bosses to Neutral
    # (teamType=14) also made them non-damageable, soft-locking players inside
    # fog-gated arenas. Bosses now stay hostile but the player's invulnerability
    # + 999x damage handles them fine.

    # === Rebuild regulation.bin ===
    print("\nRecompressing...")
    dcx_data = compress_dcx(bytes(bnd4_data), dcx_header)
    print("Re-encrypting...")
    encrypted = encrypt_regulation(dcx_data)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_REG.write_bytes(encrypted)
    print(f"Wrote: {OUTPUT_REG} ({len(encrypted):,} bytes)")


def build_msg():
    """Build modded item_dlc02.msgbnd.dcx with custom talisman text."""
    print(f"\nExtracting item_dlc02.msgbnd.dcx from game archives...")
    dcx_data = extract_from_bhd("/msg/engus/item_dlc02.msgbnd.dcx")
    print(f"  Extracted: {len(dcx_data):,} bytes")

    print("Decompressing DCX_KRAK...")
    bnd4_data, dcx_header = decompress_dcx(dcx_data)
    bnd4_data = bytearray(bnd4_data)
    entries = parse_bnd4_entries(bnd4_data)
    print(f"  BND4: {len(bnd4_data):,} bytes, {len(entries)} entries")

    # Patch DLC02 FMG files (ID 204000 is in the DLC range)
    fmg_mods = {
        'AccessoryName_dlc02.fmg': TALISMAN_NAME,
        'AccessoryInfo_dlc02.fmg': TALISMAN_SUMMARY,
        'AccessoryCaption_dlc02.fmg': TALISMAN_DESCRIPTION,
    }

    for suffix, text in fmg_mods.items():
        for idx, (ename, eoff, esize) in enumerate(entries):
            if ename.endswith(suffix):
                print(f"\n  Patching {suffix}...")
                fmg_data = bytes(bnd4_data[eoff:eoff + esize])
                fmg_entries = parse_fmg(fmg_data)
                print(f"    {len(fmg_entries)} existing entries")

                fmg_entries[CUSTOM_ACCESSORY_ID] = text
                print(f"    Added ID {CUSTOM_ACCESSORY_ID}: \"{text[:50]}{'...' if len(text) > 50 else ''}\"")

                new_fmg = build_fmg(fmg_entries)
                print(f"    FMG: {len(fmg_data)} -> {len(new_fmg)} bytes")

                bnd4_data = replace_bnd4_entry(bnd4_data, entries, idx, new_fmg)
                # Re-parse entries after rebuild
                entries = parse_bnd4_entries(bnd4_data)
                break

    # Recompress with Oodle Kraken
    print("\nRecompressing DCX_KRAK...")
    new_dcx = compress_dcx(bytes(bnd4_data), dcx_header)

    OUTPUT_MSG.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_MSG.write_bytes(new_dcx)
    print(f"Wrote: {OUTPUT_MSG} ({len(new_dcx):,} bytes)")


def load_keys(aes_key_path: Path, rsa_key_path: Path) -> None:
    """Load encryption keys from files into module globals."""
    global ER_KEY, DATA0_RSA_KEY
    ER_KEY = aes_key_path.read_bytes()
    if len(ER_KEY) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes, got {len(ER_KEY)}")
    DATA0_RSA_KEY = rsa_key_path.read_text()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Quiet Lands mod for Elden Ring")
    parser.add_argument(
        "--aes-key", type=Path,
        default=os.environ.get("QL_AES_KEY", "keys/regulation.aes"),
        help="Path to 32-byte AES key for regulation.bin (or set QL_AES_KEY env var)",
    )
    parser.add_argument(
        "--rsa-key", type=Path,
        default=os.environ.get("QL_RSA_KEY", "keys/data0.rsa.pem"),
        help="Path to RSA public key PEM for Data0.bhd (or set QL_RSA_KEY env var)",
    )
    parser.add_argument(
        "--game-dir", type=Path,
        default=os.environ.get("QL_GAME_DIR", GAME_DIR),
        help="Path to ELDEN RING/Game directory (or set QL_GAME_DIR env var)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    global GAME_DIR, REGULATION
    GAME_DIR = Path(args.game_dir)
    REGULATION = GAME_DIR / "regulation.bin"

    load_keys(Path(args.aes_key), Path(args.rsa_key))

    build_regulation()
    build_msg()

    print(f"\n{'='*60}")
    print(f"Quiet Lands mod built successfully!")
    print(f"  Talisman: \"{TALISMAN_NAME}\"")
    print(f"  Output: {OUTPUT_DIR}/")
    print(f"\nTo use:")
    print(f"  1. Copy 'mod/' folder into ModEngine2")
    print(f"  2. Launch with launchmod_eldenring.bat")
    print(f"  3. Equip \"{TALISMAN_NAME}\" to walk unseen")
    print(f"  4. Unequip it to be visible again")


if __name__ == "__main__":
    main()
