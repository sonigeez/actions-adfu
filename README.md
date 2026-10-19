# actions-adfu

Flash Actions Semiconductor **ATS30xx** firmware packages (`.fw`) over USB from
macOS, with no Windows machine and no vendor tool.

`actions-adfu` speaks the chip's USB download protocol (ADFU) directly. It reads
the same `.fw` package the vendor's Windows flashing tool uses and writes flash
the same way, then has the chip verify every region with CRC-32 before rebooting.

## Status

| | |
|---|---|
| Tested chip | ATS3085S4 (Zephyr-based SDK), full flash, macOS on Apple silicon |
| Should work | Other ATS30xx parts whose `.fw` uses the same loader (`adfus_u.bin`). Untested |
| Linux | Should work through libusb. Untested |
| Windows | Not supported. Use the vendor tool there |

On the tested firmware, the bytes this tool sends match the vendor tool's USB
traffic exactly, from the loader handshake to the final reboot command.

## Install

```bash
brew install libusb            # macOS. On Linux, install libusb-1.0 from your package manager
pip install git+https://github.com/sonigeez/actions-adfu
```

Python 3.9 or newer. The only Python dependency is `pyusb`.

## Usage

### 1. Put the device in download mode

If the firmware on the device exposes the vendor's USB mass-storage mode, put the
device in USB mode, connect it, and run:

```bash
sudo actions-adfu switch
```

This does what the vendor tool's ADFU button does: it identifies the device, then
asks it to reboot into the boot ROM's download mode (`10d6:10d6`). `sudo` is needed
because the operating system's storage driver owns the device until then.

Other ways into download mode:
- **UART console:** run `dbg reboot adfu` on the firmware's debug shell.
- **No working firmware:** the boot ROM may enter download mode on its own. Run
  `actions-adfu probe --wait 60` while you power the device on to check.

### 2. Flash

```bash
actions-adfu flash --yes-erase-flash firmware.fw
```

A typical flash takes about 25 seconds. The device reboots into the new firmware when it's done.

### Other commands

| Command | Touches the device | What it does |
|---|---|---|
| `info <fw>` | no | Lists the package contents and the flash script inside it |
| `plan <fw>` | no | Dry run that prints every USB transfer the flash would send |
| `probe [--inquiry] [--wait N]` | read-only | Lists Actions USB devices. `--inquiry` asks the boot ROM to identify itself |
| `load <fw>` | RAM only | Starts the loader and reads chip info. No flash writes. Power-cycle to undo |

## How it works

1. **Boot ROM.** In download mode the chip's mask ROM accepts USB mass-storage-style
   command blocks. The tool uploads the package's USB loader (`adfus_u.bin`) into RAM,
   reads it back to check it, and starts it.
2. **Loader.** After a short handshake, the loader takes simple fixed-size commands:
   erase, write, verify and reboot.
3. **Flash script.** The `.fw` package contains its own flash script (`product.ini`),
   listing which images go where. The tool runs it step by step, applying the same
   image preparation as the vendor tool, then asks the chip to CRC-check each region.

`plan` prints the exact traffic for any package without a device attached.

## Safety

- **Flashing replaces the firmware on the device.** Only flash packages built for your exact hardware.
- **Recovery is possible.** The boot ROM's download mode is in mask ROM and can't be
  erased, and the bootloader image is written last. A failed or interrupted flash
  should leave the chip reachable in download mode for another attempt.
- **Charge the device first.** Some devices don't charge while in download mode.

## Limitations

- **No settings editor.** The vendor tool can edit audio and EQ settings before
  flashing. This tool writes the package's configuration files as they are.
- **USB only.** UART download mode, used with the vendor's serial loader, isn't implemented.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests
```

## Disclaimer

This is an independent, interoperability-focused project. It isn't affiliated with,
endorsed by or supported by Actions Semiconductor. No vendor software is included:
the loader that runs on the chip comes from the `.fw` package you supply. Use at your
own risk.

## License

[MIT](LICENSE)
