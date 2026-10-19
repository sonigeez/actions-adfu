import struct
import unittest

from actions_adfu import firmware, protocol as P


class Checksums(unittest.TestCase):
    def test_crc16_xmodem_check_value(self):
        self.assertEqual(P.crc16(b"123456789"), 0x31C3)

    def test_crc8_poly_0x31_check_value(self):
        # CRC-8, poly 0x31, init 0, no reflection
        self.assertEqual(P.crc8(b"123456789"), 0xA2)


class Framing(unittest.TestCase):
    def test_header_round_trip(self):
        raw = P.header(1, 8, 3, 0x1234, 0x63)
        self.assertEqual(len(raw), 6)
        self.assertEqual(P.parse_header(raw), (1, 8, 3, 0x1234, 0x63))

    def test_header_rejects_bad_crc(self):
        raw = bytearray(P.header(1, 0, 0, 0, 0x63))
        raw[5] ^= 0xFF
        with self.assertRaises(IOError):
            P.parse_header(bytes(raw))

    def test_known_connect_header(self):
        self.assertEqual(P.header(1, 0, 0, 0, ord("c")).hex(), "01000000633b")
        self.assertEqual(P.ack(0).hex(), "0500000000cc")

    def test_command_layout(self):
        pkt = P.command("ws", sub=1, length=0x400, address=0x4000)
        self.assertEqual(pkt, b"ws" + struct.pack("<HIII", 1, 0x400, 0x4000, 0))

    def test_rom_cbw_layout(self):
        cbw = P.rom_write_ram_cbw(0, 0x2FF70000, 0x1000)
        self.assertEqual(len(cbw), 31)
        self.assertEqual(cbw[:4], b"USBC")
        self.assertEqual(cbw[15:17], b"\xcd\x13")
        self.assertEqual(struct.unpack_from("<II", cbw, 20), (0x1000, 0x2FF70000))
        run = P.rom_run_cbw(0, 0x2FF70001)
        self.assertEqual(struct.unpack_from("<I", run, 24)[0], 0x2FF70001)


class Sdfs(unittest.TestCase):
    def _image(self, files):
        return firmware.sdfs_add_files(firmware.sdfs_add_files(self._empty(), []), files)

    @staticmethod
    def _empty():
        head = b"sdfs.bin".ljust(12, b"\0") + struct.pack("<II", 0, 64) + bytes(4) + struct.pack("<II", 0, 0)
        return head + bytes(32)

    def test_add_files_layout_and_checksums(self):
        img = self._image([("a.bin", b"\x01\x00\x00\x00\x02"), ("b.bin", bytes(range(40)))])
        entries = firmware.sdfs_entries(img)
        self.assertEqual([e[0] for e in entries], ["a.bin", "b.bin"])
        for name, off, size in entries:
            self.assertEqual(off % 32, 0)
        (_, off_a, size_a), (_, off_b, size_b) = entries
        self.assertEqual(img[off_a:off_a + size_a], b"\x01\x00\x00\x00\x02")
        self.assertEqual(img[off_b:off_b + size_b], bytes(range(40)))
        # file checksum ignores trailing bytes that do not fill a word
        self.assertEqual(struct.unpack_from("<I", img, 32 + 28)[0], 1)
        n, total = struct.unpack_from("<II", img, 12)
        self.assertEqual((n, total), (2, len(img)))
        dir_sum, data_sum = struct.unpack_from("<II", img, 24)
        self.assertEqual(dir_sum, firmware.sum32(img[32:32 * (n + 1)]))
        self.assertEqual(data_sum, firmware.sum32(img[32 * (n + 2):total]))


if __name__ == "__main__":
    unittest.main()
