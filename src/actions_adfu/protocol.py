"""Actions ADFU download protocol, as recovered by static analysis.

Two stages, both over the same pair of bulk endpoints (OUT 0x02, IN 0x81):

Stage 1 - boot ROM ADFU (brom.hex, VID:PID 10d6:10d6)
  USB mass-storage style 31-byte CBW ("USBC"), optional data phase,
  13-byte CSW ("USBS", tag always 0, status 0 ok / 2 error).
  Opcodes: 0xCC inquiry, 0xCD vendor with subcode at CBW byte 16:
    0x13 write RAM   len = CBW[20:24], address = CBW[24:28]   (0x93 = read)
    0x20 run         entry = CBW[24:28]
    0xCC inquiry     reply length = LE u16 at CBW[22:24]

Stage 2 - adfus.bin loader running from RAM at 0x2FF70000
  Framed packets. 6-byte header:
    [0] type (1 data/control, 5 ack)   [1] chan<<4 | seq (chan 8; 0 = control)
    [2:4] payload length u16           [4] control code / ack status
    [5] CRC-8 (poly 0x31, init 0) over bytes 0..4
  Payload (if any) is preceded by CRC-16/XMODEM (poly 0x1021, init 0), LE u16.
  Every packet is acknowledged with a type-5 header, status in byte 4
  (0 ok, 0x0d CRC error -> resend, 0x1f wrong channel).
  Control codes: 'c' connect, 'o' open channel (payload u32 = 8), 'b' baud,
  'p' params, 'i' query, 'd' disconnect, 'R' reboot.
  Commands: 16-byte data packet on channel 8:
    [0:2] ASCII code  [2:4] u16 sub-arg  [4:8] u32 length  [8:12] u32 address
  Reply: 4-byte data packet, u32 status (0 ok, 3 transfer error).
"""
import struct

VID = 0x10D6
PID_ROM = 0x10D6
ADFU_PIDS = (0x10D6, 0xFF76, 0xFE02)
EP_OUT, EP_IN = 0x02, 0x81

LOADER_ADDR = 0x2FF70000
CHANNEL = 8


# ---------------------------------------------------------------- checksums
def _crc8_table(poly=0x31):
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if c & 0x80 else (c << 1) & 0xFF
        t.append(c)
    return t


def _crc16_table(poly=0x1021):
    t = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        t.append(c)
    return t


CRC8_T, CRC16_T = _crc8_table(), _crc16_table()


def crc8(data, crc=0):
    for b in data:
        crc = CRC8_T[crc ^ b]
    return crc


def crc16(data, crc=0):
    for b in data:
        crc = (CRC16_T[(crc >> 8) ^ b] ^ (crc << 8)) & 0xFFFF
    return crc


# ------------------------------------------------------------- stage 1: ROM
def cbw(tag, data_len, direction_in, cb):
    cb = bytes(cb).ljust(16, b"\0")
    return (b"USBC" + struct.pack("<IIBBB", tag, data_len, 0x80 if direction_in else 0, 0, 16) + cb)


def parse_csw(raw):
    if len(raw) != 13 or raw[:4] != b"USBS":
        raise IOError(f"bad CSW: {raw.hex()}")
    return raw[12]


def rom_write_ram_cbw(tag, address, data_len):
    cb = bytearray(16)
    cb[0], cb[1] = 0xCD, 0x13
    struct.pack_into("<II", cb, 5, data_len, address)   # CBW bytes 20..27
    return cbw(tag, data_len, False, cb)


def rom_run_cbw(tag, entry):
    cb = bytearray(16)
    cb[0], cb[1] = 0xCD, 0x20
    struct.pack_into("<I", cb, 9, entry)                # CBW bytes 24..27 (ROM skips 17..23)
    return cbw(tag, 0, False, cb)


def rom_inquiry_cbw(tag, length=11):
    # The boot ROM (sub_2B8) skips CB[1:7] and reads the reply length as LE u16 at CB[7:9],
    # not dCBWDataTransferLength. The app firmware ignores those bytes.
    cb = bytearray(16)
    cb[0] = 0xCC
    struct.pack_into("<H", cb, 7, length)
    return cbw(tag, length, True, cb)


# ---------------------------------------------------------- stage 2: loader
def header(ptype, chan, seq, length, code):
    h = struct.pack("<BBHB", ptype, ((chan & 0xF) << 4) | (seq & 0xF), length, code)
    return h + bytes([crc8(h)])


def parse_header(raw):
    if len(raw) != 6:
        raise IOError(f"short header: {raw.hex()}")
    if crc8(raw[:5]) != raw[5]:
        raise IOError(f"header CRC mismatch: {raw.hex()}")
    ptype, b1, length, code = struct.unpack_from("<BBHB", raw)
    return ptype, b1 >> 4, b1 & 0xF, length, code


def ack(code=0):
    return header(5, 0, 0, 0, code)


def command(code2, sub=0, length=0, address=0, extra=0):
    if len(code2) != 2:
        raise ValueError("command codes are two ASCII letters")
    return code2.encode() + struct.pack("<HIII", sub, length, address, extra)


class Link:
    """Bulk endpoint pair. Subclasses implement write()/read()."""

    def write(self, data):
        raise NotImplementedError

    def read(self, n, timeout_ms=5000):
        raise NotImplementedError


class RomSession:
    def __init__(self, link):
        self.link, self.tag = link, 1

    def _next(self):
        self.tag += 1
        return self.tag

    def inquiry(self):
        self.link.write(rom_inquiry_cbw(self._next()))
        data = self.link.read(11)
        status = parse_csw(self.link.read(13))
        return data, status

    def write_ram(self, address, blob, chunk=4096):
        for off in range(0, len(blob), chunk):
            part = blob[off:off + chunk]
            self.link.write(rom_write_ram_cbw(self._next(), address + off, len(part)))
            self.link.write(part)
            st = parse_csw(self.link.read(13))
            if st != 0:
                raise IOError(f"ROM write to 0x{address + off:08x} failed, CSW status {st}")

    def read_ram(self, address, length, chunk=4096):
        out = b""
        for off in range(0, length, chunk):
            n = min(chunk, length - off)
            cb = bytearray(16)
            cb[0], cb[1] = 0xCD, 0x93
            struct.pack_into("<II", cb, 5, n, address + off)
            self.link.write(cbw(self._next(), n, True, cb))
            out += self.link.read(n)
            st = parse_csw(self.link.read(13))
            if st != 0:
                raise IOError(f"ROM read from 0x{address + off:08x} failed, CSW status {st}")
        return out

    def run(self, entry):
        # The vendor tool sends the Thumb entry (0x2FF70001); the ROM ORs in bit 0 anyway.
        self.link.write(rom_run_cbw(self._next(), entry))
        st = parse_csw(self.link.read(13))
        if st != 0:
            raise IOError(f"ROM run failed, CSW status {st}")


class LoaderSession:
    def __init__(self, link):
        self.link, self.seq = link, 0

    def _send(self, ptype, chan, code, payload=b""):
        pkt = header(ptype, chan, self.seq, len(payload), code)
        if payload:
            pkt += struct.pack("<H", crc16(payload)) + payload
        self.link.write(pkt)
        self.seq = (self.seq + 1) & 0xF

    def _expect_ack(self):
        ptype, _, _, _, code = parse_header(self.link.read(6))
        if ptype != 5:
            raise IOError(f"expected ack, got packet type {ptype}")
        if code != 0:
            raise IOError(f"device NAK, status 0x{code:02x}")

    def _send_ack(self, code=0):
        self.link.write(ack(code))
        self.seq = (self.seq + 1) & 0xF

    def _recv_data(self):
        ptype, chan, _, length, code = parse_header(self.link.read(6))
        payload = b""
        if length:
            want = struct.unpack("<H", self.link.read(2))[0]
            payload = self.link.read(length)
            if crc16(payload) != want:
                self._send_ack(0x0D)
                raise IOError("payload CRC mismatch from device")
        self._send_ack(0)
        return ptype, chan, code, payload

    def control(self, code, payload=b""):
        self._send(1, 0, code, payload)
        self._expect_ack()

    def connect(self):
        self.control(ord("c"))
        self._send_ack(0)                    # device waits for our ack
        _, _, code, info = self._recv_data()  # 'r' info packet, 14 bytes
        self.control(ord("o"), struct.pack("<I", CHANNEL))
        return info

    def cmd(self, packet16, data=b"", chunk=0x4000):
        self._send(1, CHANNEL, 0, packet16)
        self._expect_ack()
        for off in range(0, len(data), chunk):
            self._send(1, CHANNEL, 0, data[off:off + chunk])
            self._expect_ack()
        _, _, _, reply = self._recv_data()
        status = struct.unpack("<I", reply[:4])[0] if len(reply) >= 4 else None
        return status

    # ---- USB mode (adfus_u.bin). Matches the vendor Windows tool on the wire.
    STATUS_OK = 0xAA

    def _read_packet(self, timeout_ms=2000):
        """One device packet: 6-byte header, then CRC-16 + payload as separate transfers."""
        ptype, chan, seq, length, code = parse_header(self.link.read(6, timeout_ms=timeout_ms))
        payload = b""
        if length:
            want = struct.unpack("<H", self.link.read(2, timeout_ms=timeout_ms))[0]
            payload = self.link.read(length, timeout_ms=timeout_ms)
            if crc16(payload) != want:
                raise IOError("payload CRC mismatch from device")
        return ptype, code, payload

    def connect_usb(self):
        """Host: 16 x 'c'. Device: connect (maybe repeated) -> host ack -> device ack ->
        'r' info (14 B) -> host ack -> 'o' open (u32 channel) -> host ack."""
        self.link.write(b"c" * 16)
        ptype, code, _ = self._read_packet()
        if (ptype, code) != (1, ord("c")):
            raise IOError(f"expected connect, got type {ptype} code 0x{code:02x}")
        self.link.write(ack(0))
        while True:                                  # skip connect retransmissions
            ptype, code, _ = self._read_packet()
            if ptype == 5:
                if code != 0:
                    raise IOError(f"device NAK 0x{code:02x} during connect")
                break
            if (ptype, code) != (1, ord("c")):
                raise IOError(f"unexpected packet type {ptype} code 0x{code:02x} during connect")
        ptype, code, info = self._read_packet()
        if code != ord("r"):
            raise IOError(f"expected info packet, got code 0x{code:02x}")
        self.link.write(ack(0))
        ptype, code, chan = self._read_packet()
        if code != ord("o") or chan[:1] != bytes([CHANNEL]):
            raise IOError(f"expected open on channel {CHANNEL}, got code 0x{code:02x} {chan.hex()}")
        self.link.write(ack(0))
        return info

    def read_cmd(self, packet16, length):
        """Commands like gf/ri return `length` raw bytes and no status word."""
        self.link.write(packet16)
        return self.link.read(length, timeout_ms=10000)

    def cmd_raw(self, packet16, data=b"", xfer=4096, timeout_ms=60000):
        self.link.write(packet16)
        for off in range(0, len(data), xfer):
            self.link.write(data[off:off + xfer])
        st = struct.unpack("<I", self.link.read(4, timeout_ms=timeout_ms))[0]
        if st != self.STATUS_OK:
            raise IOError(f"command {packet16[:2].decode()} failed, status 0x{st:08x}")
        return st

    def disconnect(self):
        self.control(ord("d"))
