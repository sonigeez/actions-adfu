"""actions-adfu: flash Actions ATS30xx firmware packages (.fw) over USB ADFU.

  info   <fw>       offline: package contents and the flash script
  plan   <fw>       offline: dry run, prints every USB transfer
  probe             device, read-only: list Actions USB devices
  switch            device (root on macOS): USB storage mode -> download mode
  load   <fw>       device, RAM only: upload + start the USB loader, connect, read chip info
  flash  <fw>       device, WRITES FLASH
"""
import argparse
import struct
import sys
import time

from . import firmware as fwfile
from . import protocol as P

# How each product.ini step is carried out.
MAPPING = {
    "adfu_switch": "switch command / device already in download mode (10d6:10d6)",
    "baudrate": "UART only; not sent over USB",
    "payload": "ROM: upload adfus_u.bin to 0x2FF70000 (verified), run 0x2FF70001, connect",
    "renew_flash_id": "loader 'gf' (2 B) + 'ri' (24 B chip info)",
    "sinit": "loader 'is'",
    "serase": "loader 'es' length=<a2> address=<a1>",
    "swrite": "loader 'es' + 'ws' (<=1 MB per command) with the image as the vendor tool writes it",
    "verify_fw": "loader 'si' sub=0x40 with {0, address, length, crc32} per written file",
    "clear_history": "loader 'es' over partition nvram_user",
    "disconnect": "loader 'af' sub=1 (device reboots)",
}
WS_MAX = 0x100000


def steps_of(fw):
    return fwfile.parse_script(fw.script())


def unmapped(steps):
    return sorted({c for c, _ in steps if c not in MAPPING})


# ------------------------------------------------------------------ links
class DryLink(P.Link):
    """Logs host->device transfers and plays a scripted, always-successful device."""

    dry = True

    def __init__(self, out=sys.stdout, max_dump=48):
        self.out, self.max_dump, self.n, self.queue = out, max_dump, 0, []

    def write(self, data):
        self.n += 1
        shown = data[:self.max_dump].hex(" ")
        more = f" ... (+{len(data) - self.max_dump} bytes)" if len(data) > self.max_dump else ""
        print(f"  OUT #{self.n:<4} {len(data):6d}B  {shown}{more}", file=self.out)
        if data == b"c" * 16:
            info, chan = bytes(14), struct.pack("<I", P.CHANNEL)
            self.queue = [P.header(1, 0, 0, 0, ord("c")), P.ack(0),
                          P.header(1, 0, 3, len(info), ord("r")), struct.pack("<H", P.crc16(info)), info,
                          P.header(1, 0, 4, 4, ord("o")), struct.pack("<H", P.crc16(chan)), chan]

    def read(self, n, timeout_ms=5000):
        if self.queue:
            return self.queue.pop(0)
        if n == 13:
            return b"USBS" + bytes(9)
        if n == 4:
            return struct.pack("<I", P.LoaderSession.STATUS_OK)
        return bytes(n)


class UsbLink(P.Link):
    def __init__(self, dev):
        self.dev = dev

    def write(self, data):
        self.dev.write(P.EP_OUT, data, timeout=5000)

    def read(self, n, timeout_ms=5000):
        buf = bytes(self.dev.read(P.EP_IN, n, timeout=timeout_ms))
        if len(buf) != n:
            raise IOError(f"short read: wanted {n}, got {len(buf)}")
        return buf


def drain(d):
    """Discard any reply left queued by an earlier, interrupted exchange."""
    import usb.core
    try:
        while True:
            print("drained stale reply:", bytes(d.read(P.EP_IN, 512, timeout=200)).hex())
    except usb.core.USBTimeoutError:
        pass


def open_usb(pids=P.ADFU_PIDS):
    try:
        import usb.core
    except ImportError:
        sys.exit("pyusb is not installed: pip install pyusb")
    devs = [d for d in usb.core.find(find_all=True, idVendor=P.VID) if d.idProduct in pids]
    return devs


# --------------------------------------------------------------- execution
def run_script(fw, link, stop_before_flash, log=print):
    dry = getattr(link, "dry", False)
    rom = P.RomSession(link)
    loader = None
    written = []                                   # (address, length, crc32) for verify_fw
    for cmd, args in steps_of(fw):
        log(f"# {cmd} {' '.join(args)}")
        if cmd in ("adfu_switch", "baudrate"):
            continue
        if cmd == "payload":
            blob = fw.get("adfus_u.bin")           # USB loader (adfus.bin is the UART one)
            rom.write_ram(P.LOADER_ADDR, blob, 4096)   # 32 KB transfers stalled on this Mac
            if not dry and rom.read_ram(P.LOADER_ADDR, len(blob)) != blob:
                raise IOError("loader read-back mismatch; not starting it")
            log(f"  loader uploaded ({len(blob)} bytes){'' if dry else ', read back and verified'}")
            rom.run(P.LOADER_ADDR | 1)
            if not dry:
                time.sleep(0.1)                    # give the loader time to bring up USB
            loader = P.LoaderSession(link)
            info = loader.connect_usb()
            log(f"  connected, loader info {info.hex(' ')}")
            continue
        if loader is None:
            raise RuntimeError("flash command before payload step")
        if cmd == "renew_flash_id":
            gf = loader.read_cmd(P.command("gf", length=2), 2)
            ri = loader.read_cmd(P.command("ri", length=0x18), 0x18)
            log(f"  gf {gf.hex(' ')} | ri {ri.hex(' ')}")
            if stop_before_flash:
                log("# stopping before any flash command (RAM-only run)")
                return
            continue
        if stop_before_flash:
            log("# stopping before any flash command (RAM-only run)")
            return
        if cmd == "sinit":
            loader.cmd_raw(P.command("is"))
        elif cmd == "serase":
            a, s = int(args[0], 0), int(args[1], 0)
            loader.cmd_raw(P.command("es", length=s, address=a), timeout_ms=120000)
        elif cmd == "swrite":
            addr, name = int(args[0], 0), args[2]
            data = fwfile.flash_image(fw, name)
            loader.cmd_raw(P.command("es", length=len(data), address=addr), timeout_ms=120000)
            for off in range(0, len(data), WS_MAX):
                part = data[off:off + WS_MAX]
                loader.cmd_raw(P.command("ws", length=len(part), address=addr + off), part)
            written.append((addr, len(data), fwfile.zlib.crc32(data)))
            log(f"  wrote {name}: {len(data)} bytes at 0x{addr:08x}")
        elif cmd == "verify_fw":
            for addr, ln, crc in written:
                loader.cmd_raw(P.command("si", sub=0x40, length=16),
                               struct.pack("<IIII", 0, addr, ln, crc), timeout_ms=120000)
            log(f"  verified {len(written)} regions by CRC-32")
        elif cmd == "clear_history":
            a, s = fwfile.partition(fw, "nvram_user")
            loader.cmd_raw(P.command("es", length=s, address=a), timeout_ms=120000)
        elif cmd == "disconnect":
            loader.cmd_raw(P.command("af", sub=1))
            log("  device is rebooting")
        else:
            raise RuntimeError(f"step '{cmd}' has no known mapping")


# -------------------------------------------------------------------- CLI
def cmd_info(a):
    fw = fwfile.Firmware(a.fw)
    print(f"{a.fw}\n\nOuter package:")
    for k, v in fw.outer.items():
        print(f"  {k:16s} {len(v):10d}")
    print("\nupgrade.fw contents:")
    for k, v in fw.files.items():
        kind = "encrypted module" if v[:16] == fwfile.ENCRYPTED_MAGIC else "data (xor 0x38)"
        print(f"  {k:24s} {len(v):10d}  {kind}")
    print("\nFlash script (product.ini):")
    for c, args in steps_of(fw):
        m = MAPPING.get(c)
        print(f"  {c:16s} {' '.join(args):36s} {'OK  ' + m if m else 'UNMAPPED'}")


def cmd_plan(a):
    fw = fwfile.Firmware(a.fw)
    link = DryLink(max_dump=a.dump)
    print("Dry run. Device replies are simulated as success.\n")
    try:
        run_script(fw, link, stop_before_flash=a.ram_only)
    except RuntimeError as e:
        print(f"\nSTOP: {e}")
    print(f"\n{link.n} OUT transfers. Unmapped steps: {', '.join(unmapped(steps_of(fw))) or 'none'}")


def wait_for_rom(seconds, log=print):
    """Poll for the boot ROM's download-mode device (10d6:10d6)."""
    import time
    import usb.core
    end, seen = time.time() + seconds, set()
    while time.time() < end:
        for d in usb.core.find(find_all=True, idVendor=P.VID):
            key = (d.idProduct, d.bus, d.address)
            if key not in seen:
                seen.add(key)
                log(f"{time.strftime('%H:%M:%S')} saw {d.idVendor:04x}:{d.idProduct:04x}")
            if d.idProduct == P.PID_ROM:
                return d
        time.sleep(0.02)
    return None


def cmd_probe(a):
    if a.wait:
        print(f"Waiting up to {a.wait}s for 10d6:10d6. Reboot the device now.", flush=True)
        d = wait_for_rom(a.wait, log=lambda m: print(m, flush=True))
        if d is None:
            print("Download-mode device never appeared.")
            return
        d.set_configuration()
        data, st = P.RomSession(UsbLink(d)).inquiry()
        print(f"ROM inquiry: {data!r}  CSW status {st}")
        return
    devs = open_usb(pids=range(0x10000))
    if not devs:
        print("No Actions (VID 10d6) USB devices found. Put the device in ADFU mode and retry.")
        return
    for d in devs:
        print(f"Found {d.idVendor:04x}:{d.idProduct:04x} bus {d.bus} addr {d.address}")
    rom = [d for d in devs if d.idProduct == P.PID_ROM]
    if rom and a.inquiry:
        d = rom[0]
        d.set_configuration()
        data, st = P.RomSession(UsbLink(d)).inquiry()
        print(f"ROM inquiry: {data!r}  CSW status {st}")


def cmd_switch(a):
    """SCSI 0xCC identify, then 0xCB reboot-to-ADFU (what the vendor tool's ADFU button does)."""
    import usb.core
    import usb.util
    devs = [d for d in usb.core.find(find_all=True, idVendor=P.VID) if d.idProduct != P.PID_ROM]
    if not devs:
        sys.exit("No Actions device in USB storage mode found (VID 10d6).")
    d = devs[0]
    print(f"Found {d.idVendor:04x}:{d.idProduct:04x} (USB storage mode)")
    try:
        if d.is_kernel_driver_active(0):
            d.detach_kernel_driver(0)
            print("Detached the OS storage driver from the device")
    except usb.core.USBError as e:
        sys.exit(f"Could not detach the OS storage driver ({e}). Run this command as root (sudo).")
    try:
        usb.util.claim_interface(d, 0)
    except usb.core.USBError as e:
        sys.exit(f"Could not claim the USB interface ({e}). Run this command as root (sudo).")
    link = UsbLink(d)
    rom = P.RomSession(link)            # same CBW/CSW framing as the firmware's MSC driver
    ident, st = rom.inquiry()
    print(f"Identify (0xCC): {ident!r}  CSW status {st}")
    if ident != b"ACTIONSUSBD":
        sys.exit("Device did not identify as an Actions ADFU-capable device. Stopping.")
    link.write(P.cbw(rom._next(), 2, True, [0xCB]))
    reply = link.read(2)
    st = P.parse_csw(link.read(13))
    print(f"Switch (0xCB): reply {reply.hex()}  CSW status {st}. Device is rebooting into download mode.")
    usb.util.dispose_resources(d)
    rd = wait_for_rom(a.wait, log=lambda m: print(m, flush=True))
    if rd is None:
        sys.exit("Download-mode device (10d6:10d6) did not appear.")
    rd.set_configuration()
    data, st = P.RomSession(UsbLink(rd)).inquiry()
    print(f"Boot ROM inquiry: {data!r}  CSW status {st}")
    print("Device is in download mode. Nothing has been written.")


def cmd_load(a):
    fw = fwfile.Firmware(a.fw)
    devs = open_usb(pids=(P.PID_ROM,))
    if not devs:
        sys.exit("No device in ROM ADFU mode (10d6:10d6).")
    d = devs[0]
    d.set_configuration()
    drain(d)
    run_script(fw, UsbLink(d), stop_before_flash=True)


def cmd_flash(a):
    fw = fwfile.Firmware(a.fw)
    missing = unmapped(steps_of(fw))
    if missing:
        sys.exit("Refusing to flash. These script steps are not yet confirmed: "
                 + ", ".join(missing) + ".")
    if not a.yes_erase_flash:
        sys.exit("Add --yes-erase-flash to confirm you want to overwrite the device flash.")
    devs = open_usb(pids=(P.PID_ROM,))
    if not devs:
        sys.exit("No device in ROM ADFU mode (10d6:10d6).")
    d = devs[0]
    d.set_configuration()
    drain(d)
    run_script(fw, UsbLink(d), stop_before_flash=False)


def main():
    ap = argparse.ArgumentParser(prog="actions-adfu", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("info"); s.add_argument("fw"); s.set_defaults(f=cmd_info)
    s = sub.add_parser("plan"); s.add_argument("fw"); s.add_argument("--dump", type=int, default=48)
    s.add_argument("--ram-only", action="store_true")
    s.set_defaults(f=cmd_plan)
    s = sub.add_parser("probe"); s.add_argument("--inquiry", action="store_true")
    s.add_argument("--wait", type=int, default=0, help="poll N seconds for 10d6:10d6, then inquire")
    s.set_defaults(f=cmd_probe)
    s = sub.add_parser("switch"); s.add_argument("--wait", type=int, default=15); s.set_defaults(f=cmd_switch)
    s = sub.add_parser("load"); s.add_argument("fw"); s.set_defaults(f=cmd_load)
    s = sub.add_parser("flash"); s.add_argument("fw"); s.add_argument("--yes-erase-flash", action="store_true")
    s.set_defaults(f=cmd_flash)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
