#!/usr/bin/env python3
"""Extract item.msgbnd.dcx from Elden Ring BHD/BDT archives.

Decrypts BHD5 header with RSA, finds the msg file by path hash,
extracts and optionally AES-decrypts the data from BDT.
"""
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import struct
import subprocess

GAME_DIR = Path("/home/ve/.steam/debian-installation/steamapps/common/ELDEN RING/Game")
PROJECT_DIR = Path(__file__).parent
OOZ_BIN = PROJECT_DIR / "ooz"

# RSA public keys for each BHD archive (from BinderTool / ER.BDT.Tool)
BHD_KEYS = {
    "Data0": """-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEA9Rju2whruXDVQZpfylVEPeNxm7XgMHcDyaaRUIpXQE0qEo+6Y36L
P0xpFvL0H0kKxHwpuISsdgrnMHJ/yj4S61MWzhO8y4BQbw/zJehhDSRCecFJmFBz
3I2JC5FCjoK+82xd9xM5XXdfsdBzRiSghuIHL4qk2WZ/0f/nK5VygeWXn/oLeYBL
jX1S8wSSASza64JXjt0bP/i6mpV2SLZqKRxo7x2bIQrR1yHNekSF2jBhZIgcbtMB
xjCywn+7p954wjcfjxB5VWaZ4hGbKhi1bhYPccht4XnGhcUTWO3NmJWslwccjQ4k
sutLq3uRjLMM0IeTkQO6Pv8/R7UNFtdCWwIERzH8IQ==
-----END RSA PUBLIC KEY-----""",
    "Data1": """-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAxaBCHQJrtLJiJNdG9nq3deA9sY4YCZ4dbTOHO+v+YgWRMcE6iK6o
ZIJq+nBMUNBbGPmbRrEjkkH9M7LAypAFOPKC6wMHzqIMBsUMuYffulBuOqtEBD11
CAwfx37rjwJ+/1tnEqtJjYkrK9yyrIN6Y+jy4ftymQtjk83+L89pvMMmkNeZaPON
4O9q5M9PnFoKvK8eY45ZV/Jyk+Pe+xc6+e4h4cx8ML5U2kMM3VDAJush4z/05hS3
/bC4B6K9+7dPwgqZgKx1J7DBtLdHSAgwRPpijPeOjKcAa2BDaNp9Cfon70oC+ZCB
+HkQ7FjJcF7KaHsH5oHvuI7EZAl2XTsLEQIENa/2JQ==
-----END RSA PUBLIC KEY-----""",
    "Data2": """-----BEGIN RSA PUBLIC KEY-----
MIIBDAKCAQEA0iDVVQ230RgrkIHJNDgxE7I/2AaH6Li1Eu9mtpfrrfhfoK2e7y4O
WU+lj7AGI4GIgkWpPw8JHaV970Cr6+sTG4Tr5eMQPxrCIH7BJAPCloypxcs2BNfT
GXzm6veUfrGzLIDp7wy24lIA8r9ZwUvpKlN28kxBDGeCbGCkYeSVNuF+R9rN4OAM
RYh0r1Q950xc2qSNloNsjpDoSKoYN0T7u5rnMn/4mtclnWPVRWU940zr1rymv4Jc
3umNf6cT1XqrS1gSaK1JWZfsSeD6Dwk3uvquvfY6YlGRygIlVEMAvKrDRMHylsLt
qqhYkZNXMdy0NXopf1rEHKy9poaHEmJldwIFAP////8=
-----END RSA PUBLIC KEY-----""",
    "Data3": """-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAvRRNBnVq3WknCNHrJRelcEA2v/OzKlQkxZw1yKll0Y2Kn6G9ts94
SfgZYbdFCnIXy5NEuyHRKrxXz5vurjhrcuoYAI2ZUhXPXZJdgHywac/i3S/IY0V/
eDbqepyJWHpP6I565ySqlol1p/BScVjbEsVyvZGtWIXLPDbx4EYFKA5B52uK6Gdz
4qcyVFtVEhNoMvg+EoWnyLD7EUzuB2Khl46CuNictyWrLlIHgpKJr1QD8a0ld0PD
PHDZn03q6QDvZd23UW2d9J+/HeBt52j08+qoBXPwhndZsmPMWngQDaik6FM7EVRQ
etKPi6h5uprVmMAS5wR/jQIVTMpTj/zJdwIEXszeQw==
-----END RSA PUBLIC KEY-----""",
}


def bhd_path_hash(path: str) -> int:
    """Compute ER BHD5 64-bit path hash."""
    h = 0
    for c in path:
        h = (ord(c) + 133 * h) & 0xFFFFFFFFFFFFFFFF
    return h


def rsa_decrypt_bhd(bhd_path: Path, key_pem: str) -> bytes:
    """Decrypt a BHD file using RSA (raw/textbook RSA, no padding).

    Output block size is key_size-1 bytes (255 for 2048-bit RSA),
    matching BouncyCastle's RsaEngine behavior.
    """
    key = RSA.import_key(key_pem)
    n = key.n
    e = key.e
    input_block = (key.size_in_bits() + 7) // 8   # 256
    output_block = input_block - 1                  # 255

    encrypted = bhd_path.read_bytes()
    result = bytearray()

    for i in range(0, len(encrypted), input_block):
        block = encrypted[i:i + input_block]
        if len(block) < input_block:
            block = block + b'\x00' * (input_block - len(block))
        ct_int = int.from_bytes(block, 'big')
        pt_int = pow(ct_int, e, n)
        # Output is output_block bytes, left-padded with zeros
        pt_bytes = pt_int.to_bytes(output_block, 'big')
        result.extend(pt_bytes)

    return bytes(result)


def parse_bhd5(data: bytes) -> list:
    """Parse decrypted BHD5, return list of entries."""
    magic = struct.unpack_from('<I', data, 0)[0]
    assert magic == 0x35444842, f"Bad BHD5 magic: 0x{magic:08X}"

    version = struct.unpack_from('<i', data, 4)[0]
    # flags at offset 8
    # data_size at offset 12
    bucket_count = struct.unpack_from('<i', data, 16)[0]
    bucket_offset = struct.unpack_from('<i', data, 20)[0]
    # salt string follows at offset 24 (null-terminated)

    entries = []
    pos = bucket_offset
    for i in range(bucket_count):
        entry_count = struct.unpack_from('<i', data, pos)[0]
        entry_offset = struct.unpack_from('<i', data, pos + 4)[0]
        pos += 8

        for j in range(entry_count):
            epos = entry_offset + j * 40  # 8+4+4+8+8+8 = 40 bytes per entry
            name_hash = struct.unpack_from('<Q', data, epos)[0]
            padded_size = struct.unpack_from('<i', data, epos + 8)[0]
            size = struct.unpack_from('<i', data, epos + 12)[0]
            offset = struct.unpack_from('<q', data, epos + 16)[0]
            sha_offset = struct.unpack_from('<q', data, epos + 24)[0]
            aes_offset = struct.unpack_from('<q', data, epos + 32)[0]

            aes_key = None
            aes_ranges = []
            if aes_offset != 0:
                aes_key = data[aes_offset:aes_offset + 16]
                range_count = struct.unpack_from('<i', data, aes_offset + 16)[0]
                for k in range(range_count):
                    roff = aes_offset + 20 + k * 16
                    r_start = struct.unpack_from('<q', data, roff)[0]
                    r_end = struct.unpack_from('<q', data, roff + 8)[0]
                    aes_ranges.append((r_start, r_end))

            entries.append({
                'hash': name_hash,
                'padded_size': padded_size,
                'size': size,
                'offset': offset,
                'aes_key': aes_key,
                'aes_ranges': aes_ranges,
            })

    return entries


def aes_decrypt_entry(data: bytearray, aes_key: bytes, ranges: list) -> bytes:
    """Decrypt entry data using AES-128-ECB for specified ranges."""
    data = bytearray(data)
    for start, end in ranges:
        if start != -1 and end != -1 and start != end:
            length = end - start
            cipher = AES.new(aes_key, AES.MODE_ECB)
            decrypted = cipher.decrypt(bytes(data[start:start + length]))
            data[start:start + length] = decrypted
    return bytes(data)


def extract_file(target_path: str, output_path: Path):
    """Extract a file from ER BHD/BDT archives by virtual path."""
    target_hash = bhd_path_hash(target_path)
    print(f"Looking for: {target_path}")
    print(f"  Hash: 0x{target_hash:016X}")

    for bhd_name, key_pem in BHD_KEYS.items():
        bhd_file = GAME_DIR / f"{bhd_name}.bhd"
        bdt_file = GAME_DIR / f"{bhd_name}.bdt"

        if not bhd_file.exists():
            continue

        print(f"\n  Trying {bhd_name}...")
        decrypted = rsa_decrypt_bhd(bhd_file, key_pem)
        entries = parse_bhd5(decrypted)
        print(f"    {len(entries)} entries")

        for entry in entries:
            if entry['hash'] == target_hash:
                print(f"    FOUND in {bhd_name} at offset {entry['offset']}, size {entry['size']}")

                raw = bytearray(bdt_file.read_bytes()[entry['offset']:entry['offset'] + entry['padded_size']])

                if entry['aes_key']:
                    print(f"    Decrypting AES...")
                    raw = aes_decrypt_entry(raw, entry['aes_key'], entry['aes_ranges'])

                # Trim to actual size (size=0 means use padded_size)
                actual_size = entry['size'] if entry['size'] > 0 else entry['padded_size']
                raw = raw[:actual_size]

                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(raw)
                print(f"    Wrote: {output_path} ({len(raw):,} bytes)")
                return True

    print("  NOT FOUND in any archive!")
    return False


def decompress_dcx_krak(dcx_path: Path, output_path: Path):
    """Decompress a DCX_KRAK file using the ooz tool."""
    result = subprocess.run(
        [str(OOZ_BIN), "-d", str(dcx_path), str(output_path)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"ooz decompress failed: {result.stderr}")
    print(f"  Decompressed: {output_path}")


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "/msg/engus/item.msgbnd.dcx"
    out = PROJECT_DIR / "work" / target.lstrip("/")

    if extract_file(target, out):
        print(f"\nExtracted to: {out}")
    else:
        print("\nExtraction failed!")
        sys.exit(1)
