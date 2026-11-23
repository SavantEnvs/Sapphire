#!/usr/bin/env python3
"""Regenerate the committed seed corpora under mayhem/<target>/testsuite/ (run from the repo root:
python3 mayhem/selftest/gen_seeds.py). Layouts mirror mayhem/selftest/fixtures.h."""
import os, struct, zlib

def out(target, name, data):
    d = os.path.join("mayhem", target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)

def frame(payloads, connection_type=1):
    body = b"".join(struct.pack("<IIIHH", 16 + len(p), 0x1111, 0x2222, 3, 0) + p for p in payloads)
    hdr = struct.pack("<QQQIHHBBHI", 0, 0, 1700000000000, 40 + len(body), connection_type, len(payloads), 0, 0, 0, 0)
    return hdr + body

# fuzz_packet: one frame, two segments; two frames back to back; an IPC-shaped segment.
out("fuzz_packet", "two_segments.bin", frame([b"ABCD", b"xyz"]))
out("fuzz_packet", "two_frames.bin", frame([b"hello"]) + frame([b"world", b"!"], 2))
ipc = struct.pack("<HHHHII", 0x14, 0x0191, 0, 0, 1700000000, 0) + b"\0" * 16
out("fuzz_packet", "ipc.bin", frame([ipc]))

# fuzz_base64
out("fuzz_base64", "hello.txt", b"aGVsbG8=")
out("fuzz_base64", "json_field.txt", b"eyJ1c2VybmFtZSI6InRlc3QiLCJwYXNzIjoieCJ9")
out("fuzz_base64", "unpadded.txt", b"TWFuTWE")

# fuzz_exd: u32 LE exh length, EXH, EXD (big-endian formats).
def exh(members, defs, variant=1, data_offset=8):
    v = b"EXHF" + struct.pack(">HHHHHHBB", 3, data_offset, len(members), len(defs), 1, 0, 0, variant)
    v = v.ljust(0x20, b"\0")
    v += b"".join(struct.pack(">HH", t, o) for t, o in members)
    v += b"".join(struct.pack(">II", s, c) for s, c in defs)
    return v + struct.pack("<H", 1)

def exd(rows, data_offset=8):
    # rows: list of (id, fixed bytes (data_offset long), string blob)
    index = b""
    recs = b""
    base = 0x20 + 8 * len(rows)
    for rid, fixed, strings in rows:
        index += struct.pack(">II", rid, base + len(recs))
        payload = fixed + strings
        recs += struct.pack(">IH", len(payload), 1) + payload
    return (b"EXDF" + struct.pack(">HHI", 2, 0, len(index))).ljust(0x20, b"\0") + index + recs

e1 = exh([(7, 0), (0, 4)], [(0, 2)])
d1 = exd([(0, struct.pack(">II", 0x12345678, 0), b"hi\0"), (1, struct.pack(">II", 42, 0), b"yo\0")])
out("fuzz_exd", "uint32_string.bin", struct.pack("<I", len(e1)) + e1 + d1)
e2 = exh([(1, 0), (2, 1), (3, 2), (4, 3), (5, 5), (6, 7), (9, 11), (11, 15), (0x19, 23)], [(10, 3)], data_offset=24)
fixed = struct.pack(">BbBhHiIfQ", 1, -2, 3, -4, 5, -6, 7, 1.5, 8)[:23] + b"\x01"
d2 = exd([(10, fixed, b""), (11, fixed, b""), (12, fixed, b"")], data_offset=24)
out("fuzz_exd", "all_types.bin", struct.pack("<I", len(e2)) + e2 + d2)
e3 = exh([(7, 0)], [(0, 1)], variant=2, data_offset=4)
d3 = exd([(0, struct.pack(">HI", 0, 99), b"")], data_offset=4)
out("fuzz_exd", "subrows.bin", struct.pack("<I", len(e3)) + e3 + d3)

# fuzz_sqpack: one file that is both a valid .index (hash table at 0x800 -> file at 0x1000)
# and a .dat whose entry at 0x1000 is a standard file with one deflate block + one raw block.
def sqpack():
    hdr = b"SqPack\0\0" + bytes([0, 0, 0, 0]) + struct.pack("<III", 0x400, 1, 2)
    v = bytearray(hdr.ljust(0x400, b"\0"))
    v += struct.pack("<II", 0x400, 2)                         # SqPackIndexHeader
    v += struct.pack("<II", 0x800, 16) + b"\0" * 64            # IndexBlockRecord / DatBlockRecord head
    v = v.ljust(0x800, b"\0")
    v += struct.pack("<IIII", 0xAAAA, 0xBBBB, 0x200, 0)        # -> datOffset (0x200 & ~0xF) * 8 = 0x1000
    v = v.ljust(0x1000, b"\0")
    payload = b"Sapphire sqpack fuzz seed! " * 4
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    c = comp.compress(payload) + comp.flush()
    raw = b"RAWBLOCK"
    hsize = 0x80
    blk1 = struct.pack("<IIII", 16, 0, len(c), len(payload)) + c
    blk2 = struct.pack("<IIII", 16, 0, 32000, len(raw)) + raw
    fh = struct.pack("<IIIII", hsize, 2, len(payload) + len(raw), 0, 0)
    fh += struct.pack("<I", 2) + struct.pack("<IHH", 0, len(blk1), len(payload)) + struct.pack("<IHH", len(blk1), len(blk2), len(raw))
    v += fh.ljust(hsize, b"\0") + blk1 + blk2
    return bytes(v)
out("fuzz_sqpack", "index_and_standard_file.bin", sqpack())

# fuzz_navmesh: u32 LE .nav length, .nav (TSET), optional .navmesh_cache.
TSET = (ord('T') << 24) | (ord('S') << 16) | (ord('E') << 8) | ord('T')
def tset(num_tiles=0, tiles=b""):
    v = struct.pack("<iii", TSET, 1, num_tiles)
    v += struct.pack("<fffffii", 0, 0, 0, 48, 48, 64, 4096)
    v += struct.pack("<fffffiiffffii", 0, 0, 0, 0.25, 0.2, 192, 192, 2, 0.6, 0.9, 1.3, 256, 128)
    return v + tiles
def mesh_tile():
    # dtMeshHeader (DNAV v7) for a one-triangle tile.
    DNAV = (ord('D') << 24) | (ord('N') << 16) | (ord('A') << 8) | ord('V')
    h = struct.pack("<iiiiiIiiiiiiiii", DNAV, 7, 0, 0, 0, 0, 1, 3, 3, 1, 0, 1, 0, 0, 1)
    h += struct.pack("<fff", 2, 0.6, 0.9) + struct.pack("<ffffff", 0, 0, 0, 10, 1, 10) + struct.pack("<f", 4)
    verts = struct.pack("<9f", 0, 0, 0, 10, 0, 0, 0, 0, 10)
    poly = struct.pack("<I", 0) + struct.pack("<6H", 0, 1, 2, 0, 0, 0) + struct.pack("<6H", 0, 0, 0, 0, 0, 0) + struct.pack("<HBB", 1, 3, 1)
    links = b"\0" * (12 * 3)
    dmesh = struct.pack("<IIBBxx", 0, 0, 0, 1)
    dtris = bytes([0, 1, 2, 0x15])
    return h + verts + poly + links + dmesh + dtris
nav = tset()
out("fuzz_navmesh", "tset_empty.bin", struct.pack("<I", len(nav)) + nav)
cache = struct.pack("<III", 0xFF14DEAD, 1, 1)
t = mesh_tile()
cache += struct.pack("<I", len(t)) + t
out("fuzz_navmesh", "tset_with_cache.bin", struct.pack("<I", len(nav)) + nav + cache)
tile = bytes(range(64)) * 4
nav2 = tset(1, struct.pack("<Ii", 1, len(tile)) + tile)
out("fuzz_navmesh", "tset_one_tile.bin", struct.pack("<I", len(nav2)) + nav2)

# fuzz_nav_convert: RecastDemo MSET set holding the same one-triangle tile.
MSET = (ord('M') << 24) | (ord('S') << 16) | (ord('E') << 8) | ord('T')
mset = struct.pack("<iii", MSET, 1, 1) + struct.pack("<fffffii", 0, 0, 0, 48, 48, 64, 4096)
out("fuzz_nav_convert", "one_tile.bin", mset + struct.pack("<Ii", 1 << 18, len(t)) + t)
out("fuzz_nav_convert", "no_tiles.bin", struct.pack("<iii", MSET, 1, 0) + struct.pack("<fffffii", 0, 0, 0, 48, 48, 64, 4096))
