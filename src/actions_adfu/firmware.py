"""Read Actions ATS30xx .fw firmware packages (ACTTEST0 container).

Layout:
  .fw            "ACTTEST0" header, 32-byte file table at 0x20:
                 name[16], offset u32, length u32, reserved u32, crc u32
  upgrade.fw     16-byte Actions header, then a FAT32 image ("ACTS-FWT001")
  files inside   XOR 0x38 byte-wise (data files) or an encrypted container
                 (compiled Python modules, header 11 22 33 .. ff 75), which
                 this tool never needs.
"""
import re
import zlib
import struct

XOR_KEY = 0x38
ENCRYPTED_MAGIC = bytes.fromhex("112233445566778899aabbccddeeff75")


def xor_decode(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def read_outer(path):
    """Return {name: bytes} for the ACTTEST0 file table."""
    d = open(path, "rb").read()
    if d[:8] != b"ACTTEST0":
        raise ValueError("not an Actions .fw package (missing ACTTEST0 magic)")
    files, i = {}, 0x20
    while i + 32 <= len(d):
        raw = d[i:i + 16].split(b"\0")[0]
        if not raw or not all(32 < c < 127 for c in raw):
            break
        off, ln = struct.unpack_from("<II", d, i + 16)
        files[raw.decode()] = d[off:off + ln]
        i += 32
    return files


def read_fat32(img: bytes):
    """Minimal FAT32 reader with long-name support. Returns {path: bytes}."""
    bps, spc, rsv, nfat = struct.unpack_from("<HBHB", img, 11)
    spf = struct.unpack_from("<I", img, 36)[0]
    root = struct.unpack_from("<I", img, 44)[0]
    fat = rsv * bps
    data = (rsv + nfat * spf) * bps
    cs = bps * spc

    def chain(c):
        while 2 <= c < 0x0FFFFFF8:
            yield c
            c = struct.unpack_from("<I", img, fat + 4 * c)[0] & 0x0FFFFFFF

    def read(c, size=None):
        b = b"".join(img[data + (x - 2) * cs:data + (x - 1) * cs] for x in chain(c))
        return b if size is None else b[:size]

    out = {}

    def walk(c, prefix):
        raw, lfn = read(c), []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            if e[11] == 0x0F:
                lfn.insert(0, e[1:11] + e[14:26] + e[28:32])
                continue
            if lfn:
                name = b"".join(lfn).decode("utf-16le", "ignore")
                name = name.split("\0")[0].rstrip("￿")
                # The Actions packer appends a "~<n>" version suffix to long names.
                name = re.sub(r"~\d+$", "", name)
            else:
                base, ext = e[:8].decode("latin1").strip(), e[8:11].decode("latin1").strip()
                name = base + ("." + ext if ext else "")
            lfn = []
            if name in (".", "..") or e[11] & 0x08:
                continue
            cl = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            path = f"{prefix}{name}"
            if e[11] & 0x10:
                walk(cl, path + "/")
            else:
                out[path] = read(cl, size)

    walk(root, "")
    return out


class Firmware:
    def __init__(self, path):
        self.path = path
        self.outer = read_outer(path)
        if "upgrade.fw" not in self.outer:
            raise ValueError("package has no upgrade.fw")
        upg = self.outer["upgrade.fw"]
        # The FAT boot sector starts after a 16-byte Actions header.
        self.files = read_fat32(upg[0x10:])

    def get(self, name):
        """Decoded contents of a data file inside upgrade.fw."""
        raw = self.files[name]
        if raw[:16] == ENCRYPTED_MAGIC:
            raise ValueError(f"{name} is an encrypted module, not a data file")
        return xor_decode(raw)

    def script(self):
        return self.get("product.ini").decode("latin1")


def parse_script(text):
    """Turn product.ini into a list of (command, [args]) tuples."""
    steps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" in line:
            k, v = (s.strip() for s in line.split("=", 1))
            steps.append((k, [v]))
        else:
            parts = line.split()
            steps.append((parts[0], parts[1:]))
    return steps


# ------------------------------------------------------------------ SDFS
# Small read-only file system used for sdfs.bin / ksdfs.bin.
#   entry 0: "sdfs.bin", u32 file count @12, u32 total size @16,
#            u32 sum32(file entries) @24, u32 sum32(data area) @28
#   entry i: name[12], u32 offset @12, u32 size @16, zeros, u32 file checksum @28
#   file checksum = sum of the file's complete LE u32 words (trailing 1-3 bytes ignored);
#   header sums use sum32 over 32-byte-aligned areas.
def sum32(b):
    b = b + bytes(-len(b) % 4)
    return sum(struct.unpack_from(f"<{len(b) // 4}I", b)) & 0xFFFFFFFF


def sum32_full_words(b):
    n = len(b) // 4
    return sum(struct.unpack_from(f"<{n}I", b)) & 0xFFFFFFFF


def sdfs_entries(img):
    n = struct.unpack_from("<I", img, 12)[0]
    out = []
    for i in range(1, n + 1):
        e = img[i * 32:(i + 1) * 32]
        off, size = struct.unpack_from("<II", e, 12)
        out.append((e[:12].split(b"\0")[0].decode("latin1"), off, size))
    return out


def sdfs_add_files(img, extra):
    """Append files to an existing SDFS image the way the vendor Windows tool does:
    keep the original data area byte-for-byte (shifted for the larger directory),
    append each new file at the next 32-byte boundary."""
    old = sdfs_entries(img)
    old_total = struct.unpack_from("<I", img, 16)[0]
    old_first = (len(old) + 2) * 32
    n = len(old) + len(extra)
    first = (n + 2) * 32
    shift = first - old_first
    entries = [(name, off + shift, size, img[off:off + size]) for name, off, size in old]
    data = bytearray(img[old_first:old_total])
    cursor = old_total + shift
    for name, blob in extra:
        if len(name.encode()) > 11:
            raise ValueError(f"SDFS name too long: {name}")
        pad = cursor - (first + len(data))
        data += bytes(pad) + blob
        entries.append((name, cursor, len(blob), blob))
        cursor = (cursor + len(blob) + 31) & ~31
    data += bytes(cursor - (first + len(data)))
    dirb = b"".join(name.encode().ljust(12, b"\0") + struct.pack("<II", off, size) + bytes(8)
                    + struct.pack("<I", sum32_full_words(blob)) for name, off, size, blob in entries)
    head = b"sdfs.bin".ljust(12, b"\0") + struct.pack("<II", n, cursor) + bytes(4) \
        + struct.pack("<II", sum32(dirb), sum32(bytes(data)))
    return head + dirb + bytes(32) + bytes(data)


# Config files the vendor tool merges into sdfs.bin when flashing, in its order.
# Its settings editors would change their contents; this tool uses them as packaged.
SDFS_CONFIG_FILES = ["defcfg.bin", "usrcfg.bin", "cfg_mic.bin", "extcfg.bin", "alcfg.bin"]


def flash_image(fw, name):
    """Bytes actually written to flash for a script file (matches the vendor tool)."""
    data = fw.get(name)
    if name == "app.bin" and "ksdfs.bin" in fw.files:
        data += fw.get("ksdfs.bin")
    elif name == "sdfs.bin":
        extra = [(f, fw.get(f)) for f in SDFS_CONFIG_FILES if f in fw.files]
        if extra:
            data = sdfs_add_files(data, extra)
    return data


def partition(fw, part_name):
    x = fw.get("firmware.xml").decode("latin1")
    for m in re.finditer(r"<partition>(.*?)</partition>", x, re.S):
        blk = m.group(1)

        def g(k):
            mm = re.search(rf"<{k}>([^<]*)</{k}>", blk)
            return mm.group(1).strip() if mm else ""
        if g("name") == part_name:
            return int(g("address"), 0), int(g("size"), 0)
    raise KeyError(part_name)
