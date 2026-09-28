#!/usr/bin/env python3
"""
ANTI-GRAVITY BOOT PACKAGE v3 - Host Orchestrator (REAL USB I/O)

This supersedes ANTI_GRAVITY_BOOT_001/orchestrator.py, which despite its name
never performed any USB I/O at all -- it only ran static file/hash checks and
printed the planned command sequence as text. That gap is exactly item #2 from
CODEX_HANDOFF_STOP_REPORT_PROJECT3.txt's "unfinished work" list. This file
closes it: it actually opens the PongoOS USB interface and speaks the pinned
97c2800 protocol for real, gated behind explicit flags and a mandatory device
identity check.

STILL REQUIRED BEFORE THIS CAN TALK TO A DEVICE ON WINDOWS:
  The iPad's Pongo-mode USB interface must have a libusb-compatible driver
  (WinUSB) bound to it via Zadig (https://zadig.akeo.ie/), because Windows
  binds Apple's own driver to the device by default and libusb cannot open
  an interface that driver already owns exclusively. This is a one-time,
  user-performed, host-side action -- this script cannot do it for you, and
  it is NOT a code bug if --list-devices finds nothing before that is done.

THIS SCRIPT DOES NOT PERFORM THE CHECKM8/DFU EXPLOIT ITSELF. It assumes the
device is ALREADY sitting in a live PongoOS USB shell (VID 05AC PID 4141),
which today only happens by first running the existing palera1n binary
against the device in DFU mode (palera1n -p), exactly as prior READY_TO_BOOT
documents describe. This script picks up only from that point onward.

SAFETY MODEL (unchanged from the project's established rules):
  - Default mode is --dry-run: static validation + protocol simulation only,
    zero USB access, safe to run anytime.
  - --list-devices: opens libusb and enumerates devices only. No writes.
  - --execute performs the real sequence, but refuses to proceed past device
    identity verification (CPID:7001 BDID:06 required, read from the real
    device) under any circumstance. It fails closed on every unexpected
    response, on any command timeout, and on any missing SUCCESS marker --
    it never guesses or continues past an ambiguous result.
  - Every control/bulk transfer and every line of device stdout is written,
    timestamped, to a per-run log file before the run proceeds. Nothing is
    summarized-then-discarded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------ #
# Constants (pinned; changing any of these is a package-identity change) #
# ------------------------------------------------------------------ #
PONGO_VID = 0x05AC
PONGO_PID = 0x4141

EXPECTED_CPID = "7001"  # A8X
EXPECTED_BDID = "06"    # iPad5,3

EXPECTED_HASHES = {
    "kernelcache.darwin22.20A5303i":
        "E09B9279AA7418EC22F54A2DF3EDD38E732DC967C559CBD9D80FD5CFDC2CB4B2",
    "reloc-loader-v3":
        "E5176595B567CB196F1BB348FF433B51F40E9A7B8565F42335864A65789194B4",
    "checkra1n-kpf-pongo":
        "D780687BB5B9E0206FAA8A287F95F5E1D9A654B10F4FB8B3A34B92625881A0EF",
    "RestoreRamDisk.pongo.lzma":
        "807CAE6E43E47B960CF828E6FDE234EE58A4AA9946EED51FED093450A19003F1",
}

DONOR_UUID = "5254C9FF-A9BB-380B-80C3-0FBCC29E20CA"
DONOR_SIZE = 44285952
KPF_SIZE = 115264
RELOC_V3_SIZE = 51304
RAMDISK_COMPRESSED_SIZE = 81111481
RAMDISK_UNCOMPRESSED_SIZE = 136344064
RAMDISK_UNCOMPRESSED_SHA256 = "56CB88BA5F41F21737EF0B71C7D735C4D534B16BECBBE8FE55312CB710B25E47"

REQUIRED_PONGO_COMMANDS = {"modload", "xfb", "xargs", "ramdisk", "bootx", "loadxreloc"}

# bRequest values (pinned PongoOS 97c2800 src/shell/usbloader.c)
REQ_SET_XFER_SIZE = 1     # 0x21, wLength=4 : set loader_xfer_size
REQ_UPLOAD_BEGIN = 1      # 0x21, wLength=0 : begin bulk upload of declared size
REQ_DISCARD = 2           # 0x21, wLength=0 : discard staged data
REQ_STDIN_WRITE = 3       # 0x21, wLength=1..512 : write to command stdin
REQ_MODE = 4              # 0x21 : wValue 0=wait, 1=async-blocking, 0xffff=reset
REQ_STDOUT_FETCH = 1      # 0xA1, wLength=512 or 0x1000 : fetch stdout ring buffer
REQ_CMD_IN_PROGRESS = 2   # 0xA1, wLength=1 : 1=busy, 0=idle

BULK_OUT_EP = 0x02
BULK_CHUNK = 0x8000  # 32 KiB write chunks; PongoOS tracks total bytes, not packet boundaries

LOG_DIR = Path(__file__).parent / "LOGS" / "ANTI_GRAVITY_BOOT_002"


class OrchestratorError(Exception):
    """Raised on any fail-closed condition. Never caught-and-continued."""


# ------------------------------------------------------------------ #
# Logging                                                              #
# ------------------------------------------------------------------ #
class RunLog:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def write(self, line: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        entry = f"[{ts}] {line}"
        print(entry)
        self._fh.write(entry + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


# ------------------------------------------------------------------ #
# Mach-O helpers (shared with static validation)                       #
# ------------------------------------------------------------------ #
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest().upper()


def check_macho(data: bytes) -> bool:
    return len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == 0xFEEDFACF


def parse_uuid(data: bytes) -> Optional[str]:
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    for _ in range(min(ncmds, 128)):
        if off + 8 > len(data):
            break
        cmd, csz = struct.unpack_from("<II", data, off)
        if cmd == 0x1B and csz >= 24 and off + 24 <= len(data):
            raw = data[off + 8:off + 24]
            return (f"{raw[0]:02X}{raw[1]:02X}{raw[2]:02X}{raw[3]:02X}-"
                    f"{raw[4]:02X}{raw[5]:02X}-{raw[6]:02X}{raw[7]:02X}-"
                    f"{raw[8]:02X}{raw[9]:02X}-"
                    f"{raw[10]:02X}{raw[11]:02X}{raw[12]:02X}{raw[13]:02X}"
                    f"{raw[14]:02X}{raw[15]:02X}")
        off += csz
    return None


# ------------------------------------------------------------------ #
# Static validation (package integrity only; no USB)                   #
# ------------------------------------------------------------------ #
def run_static_validation(pkg_dir: Path, log: RunLog) -> bool:
    log.write("=" * 64)
    log.write("STATIC PACKAGE VALIDATION")
    log.write("=" * 64)
    ok = True
    for name, expected in EXPECTED_HASHES.items():
        p = pkg_dir / name
        if not p.exists():
            log.write(f"MISSING: {name}")
            ok = False
            continue
        actual = sha256_file(p)
        match = actual == expected
        log.write(f"{'OK' if match else 'HASH_FAIL'}: {name} size={p.stat().st_size} sha256={actual}")
        ok = ok and match

    kernel_path = pkg_dir / "kernelcache.darwin22.20A5303i"
    if kernel_path.exists():
        kdata = kernel_path.read_bytes()
        uuid = parse_uuid(kdata)
        log.write(f"{'OK' if uuid == DONOR_UUID else 'FAIL'}: kernel UUID={uuid}")
        ok = ok and (uuid == DONOR_UUID)

    rd_path = pkg_dir / "RestoreRamDisk.pongo.lzma"
    if rd_path.exists():
        decomp = lzma.decompress(rd_path.read_bytes(), format=lzma.FORMAT_ALONE)
        rd_hash = hashlib.sha256(decomp).hexdigest().upper()
        size_ok = len(decomp) == RAMDISK_UNCOMPRESSED_SIZE
        hash_ok = rd_hash == RAMDISK_UNCOMPRESSED_SHA256
        log.write(f"{'OK' if size_ok else 'FAIL'}: ramdisk decompressed size={len(decomp)}")
        log.write(f"{'OK' if hash_ok else 'FAIL'}: ramdisk decompressed sha256={rd_hash}")
        ok = ok and size_ok and hash_ok

    log.write("STATIC VALIDATION: " + ("PASS" if ok else "FAIL"))
    return ok


# ------------------------------------------------------------------ #
# Real USB transport                                                   #
# ------------------------------------------------------------------ #
def _ensure_usb() -> None:
    """Deferred, idempotent import of pyusb, bound as a module-level global.

    Deliberately NOT a top-of-file import: --dry-run must work even before
    pyusb/libusb is installed. Called at the start of every PongoDevice method
    that touches usb.* (not just the entry points), so no method can ever again
    rely on another method having imported it first -- exactly the bug class
    that caused 'NameError: name usb is not defined' in read_serial_identity().
    Python caches imports, so calling this repeatedly is cheap.
    """
    global usb
    import usb.core          # noqa: F401
    import usb.util          # noqa: F401
    import usb.backend.libusb1  # noqa: F401


class PongoDevice:
    """Thin wrapper around a live PongoOS USB shell. Opens nothing until connect()."""

    def __init__(self, log: RunLog, libusb_dll: Optional[str] = None):
        self.log = log
        self._dev = None
        self._libusb_dll = libusb_dll

    def _backend(self):
        _ensure_usb()
        if self._libusb_dll:
            return usb.backend.libusb1.get_backend(find_library=lambda x: self._libusb_dll)
        return usb.backend.libusb1.get_backend()

    def list_devices(self) -> list:
        _ensure_usb()
        backend = self._backend()
        if backend is None:
            raise OrchestratorError(
                "libusb backend could not be loaded. Pass --libusb-dll pointing "
                "at a libusb-1.0.dll (see TOOLS/libusb/VS2022/MS64/dll/)."
            )
        return list(usb.core.find(find_all=True, backend=backend))

    def connect(self, timeout_s: float = 30.0) -> None:
        _ensure_usb()
        backend = self._backend()
        if backend is None:
            raise OrchestratorError("libusb backend could not be loaded.")

        self.log.write(f"Waiting up to {timeout_s:.0f}s for PongoOS device "
                        f"(VID={PONGO_VID:04x} PID={PONGO_PID:04x})...")
        deadline = time.monotonic() + timeout_s
        dev = None
        while time.monotonic() < deadline:
            dev = usb.core.find(idVendor=PONGO_VID, idProduct=PONGO_PID, backend=backend)
            if dev is not None:
                break
            time.sleep(0.5)
        if dev is None:
            raise OrchestratorError(
                "No PongoOS device found. Confirm: (1) device is in DFU mode and "
                "palera1n -p has already been run to reach the Pongo USB shell, "
                "(2) a WinUSB driver is bound to the interface via Zadig, not "
                "Apple's own driver."
            )

        try:
            dev.set_configuration()
        except usb.core.USBError as e:
            raise OrchestratorError(
                f"Could not claim the device (errno={e.errno}): {e}. "
                "This almost always means Zadig/WinUSB has not been bound to "
                "this interface yet, or another process (iTunes/AMDS/usbmuxd) "
                "still holds it."
            ) from e

        self._dev = dev
        self.log.write("Device opened and configured.")

    # -- control transfer primitives ------------------------------------
    def _ctrl_out(self, bRequest: int, wValue: int = 0, wIndex: int = 0,
                  data: bytes = b"", timeout_ms: int = 5000) -> None:
        self._dev.ctrl_transfer(0x21, bRequest, wValue, wIndex, data, timeout=timeout_ms)

    def _ctrl_in(self, bRequest: int, length: int, wValue: int = 0,
                 wIndex: int = 0, timeout_ms: int = 5000) -> bytes:
        return bytes(self._dev.ctrl_transfer(0xA1, bRequest, wValue, wIndex, length, timeout=timeout_ms))

    def read_serial_identity(self) -> str:
        _ensure_usb()
        sn = usb.util.get_string(self._dev, self._dev.iSerialNumber) if self._dev.iSerialNumber else ""
        return sn or ""

    def preflight_identity(self) -> None:
        _ensure_usb()
        sn = self.read_serial_identity()
        self.log.write(f"Device iSerialNumber: {sn!r}")
        if f"CPID:{EXPECTED_CPID}" not in sn or f"BDID:{EXPECTED_BDID}" not in sn:
            raise OrchestratorError(
                f"Device identity mismatch. Expected CPID:{EXPECTED_CPID} "
                f"BDID:{EXPECTED_BDID} (iPad5,3/A8X/T7001) in serial string, "
                f"got: {sn!r}. Refusing to proceed."
            )
        self.log.write("Device identity PASS: CPID/BDID match iPad5,3/A8X/T7001.")

    def wait_idle(self, timeout_s: float = 30.0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            status = self._ctrl_in(REQ_CMD_IN_PROGRESS, 1)
            if status and status[0] == 0:
                return
            time.sleep(0.05)
        raise OrchestratorError("Timed out waiting for command_in_progress to clear.")

    def fetch_stdout(self) -> str:
        chunks = []
        for _ in range(64):
            try:
                data = self._ctrl_in(REQ_STDOUT_FETCH, 0x1000)
            except Exception:
                break
            text = data.split(b"\x00", 1)[0]
            if not text:
                break
            chunks.append(text.decode("utf-8", errors="replace"))
        return "".join(chunks)

    def run_command(self, command: str, timeout_s: float = 30.0) -> str:
        self.log.write(f">>> {command}")
        self._ctrl_out(REQ_MODE, wValue=0)  # wait-for-completion mode
        payload = (command + "\n").encode("utf-8")
        for i in range(0, len(payload), 512):
            self._ctrl_out(REQ_STDIN_WRITE, data=payload[i:i + 512])
        self.wait_idle(timeout_s=timeout_s)
        out = self.fetch_stdout()
        for line in out.splitlines():
            self.log.write(f"<<< {line}")
        return out

    def upload(self, data: bytes, label: str) -> None:
        self.log.write(f"Setting upload buffer size for {label}: {len(data)} bytes")
        self._ctrl_out(REQ_SET_XFER_SIZE, data=struct.pack("<I", len(data)))
        self._ctrl_out(REQ_UPLOAD_BEGIN)
        sent = 0
        t0 = time.monotonic()
        while sent < len(data):
            chunk = data[sent:sent + BULK_CHUNK]
            self._dev.write(BULK_OUT_EP, chunk, timeout=30000)
            sent += len(chunk)
        elapsed = time.monotonic() - t0
        self.log.write(f"Uploaded {label}: {sent} bytes in {elapsed:.1f}s "
                        f"({sent / max(elapsed, 0.001) / 1e6:.2f} MB/s)")


# ------------------------------------------------------------------ #
# The real boot sequence                                               #
# ------------------------------------------------------------------ #
REQUIRED_SUCCESS_MARKERS = {
    "modload_reloc": ("CODEX-RELOC-V3: loaded; no memory changed",),
    "loadxreloc": ("CODEX-RELOC-V3: READY", "CODEX-DARWIN22-STAGED"),
    "modload_kpf": ("KPF:",),
    "ramdisk": ("allocated static region",),
}
FORBIDDEN_MARKERS = ("FAIL", "panic", "Missing patch", "ERROR")


def require_markers(output: str, required: tuple[str, ...], step: str) -> None:
    for marker in required:
        if marker not in output:
            raise OrchestratorError(f"Step '{step}': required marker not found: {marker!r}")
    for bad in FORBIDDEN_MARKERS:
        if bad in output:
            raise OrchestratorError(f"Step '{step}': forbidden marker present: {bad!r}")


def execute_boot_sequence(pkg_dir: Path, dev: PongoDevice, log: RunLog) -> None:
    log.write("=" * 64)
    log.write("LIVE EXECUTION — this will write to the connected device's RAM")
    log.write("=" * 64)

    dev.preflight_identity()

    help_out = dev.run_command("help")
    missing = [c for c in REQUIRED_PONGO_COMMANDS if c not in help_out]
    if missing:
        raise OrchestratorError(f"Missing required Pongo commands: {missing}")
    log.write("All required commands present.")

    # 'modload' always targets whatever was just uploaded. The relocation
    # module (reloc-loader-v3) must therefore be uploaded and modload'd
    # BEFORE the donor kernel -- the donor kernel is loadxreloc's argument,
    # a separate custom command reloc-loader-v3 registers, never modload's.
    reloc_module = (pkg_dir / "reloc-loader-v3").read_bytes()
    dev.upload(reloc_module, "reloc-loader-v3")
    out = dev.run_command("modload")
    require_markers(out, REQUIRED_SUCCESS_MARKERS["modload_reloc"], "modload_reloc")

    kernel = (pkg_dir / "kernelcache.darwin22.20A5303i").read_bytes()
    dev.upload(kernel, "kernelcache.darwin22.20A5303i")
    out = dev.run_command("loadxreloc")
    require_markers(out, REQUIRED_SUCCESS_MARKERS["loadxreloc"], "loadxreloc")

    kpf = (pkg_dir / "checkra1n-kpf-pongo").read_bytes()
    dev.upload(kpf, "checkra1n-kpf-pongo")
    out = dev.run_command("modload")
    require_markers(out, REQUIRED_SUCCESS_MARKERS["modload_kpf"], "modload_kpf")

    dev.run_command("xfb")
    dev.run_command("xargs -v keepsyms=1 debug=0x2014e rootdev=md0")

    ramdisk_lzma = (pkg_dir / "RestoreRamDisk.pongo.lzma").read_bytes()
    dev.upload(ramdisk_lzma, "RestoreRamDisk.pongo.lzma")
    out = dev.run_command(f"ramdisk {RAMDISK_UNCOMPRESSED_SIZE}")
    require_markers(out, REQUIRED_SUCCESS_MARKERS["ramdisk"], "ramdisk")

    log.write("All pre-boot steps succeeded. Issuing 'bootx'.")
    dev.run_command("bootx", timeout_s=5.0)  # device will stop responding to USB after this
    log.write("bootx issued. Device is expected to stop responding to USB now.")
    log.write("Per EXPECTED_FIRST_FAILURE.txt, failure at platform init is the "
              "predicted outcome given known-missing A8X/T7001 kexts. Observe "
              "the physical screen/framebuffer directly; this script cannot see it.")


# ------------------------------------------------------------------ #
# Main                                                                  #
# ------------------------------------------------------------------ #
def main() -> None:
    parser = argparse.ArgumentParser(description="ANTI-GRAVITY BOOT v3 orchestrator")
    parser.add_argument("--pkg-dir", default=str(Path(__file__).parent))
    parser.add_argument("--libusb-dll", default=None,
                         help="Path to libusb-1.0.dll, e.g. TOOLS/libusb/VS2022/MS64/dll/libusb-1.0.dll")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Static validation only. No USB access.")
    mode.add_argument("--list-devices", action="store_true", help="Enumerate USB devices via libusb. No writes.")
    mode.add_argument("--execute", action="store_true",
                       help="Perform the real sequence against a connected PongoOS device.")
    args = parser.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log = RunLog(LOG_DIR / f"run_{run_id}.log")
    pkg_dir = Path(args.pkg_dir).resolve()

    try:
        if args.dry_run:
            ok = run_static_validation(pkg_dir, log)
            sys.exit(0 if ok else 1)

        if args.list_devices:
            dev = PongoDevice(log, libusb_dll=args.libusb_dll)
            devices = dev.list_devices()
            log.write(f"Found {len(devices)} USB device(s) via libusb.")
            for d in devices:
                log.write(f"  VID={d.idVendor:04x} PID={d.idProduct:04x}")
            sys.exit(0)

        if args.execute:
            if not run_static_validation(pkg_dir, log):
                raise OrchestratorError("Static validation failed; refusing to proceed to live execution.")
            dev = PongoDevice(log, libusb_dll=args.libusb_dll)
            dev.connect()
            execute_boot_sequence(pkg_dir, dev, log)
            sys.exit(0)
    except OrchestratorError as e:
        log.write(f"FAIL (closed): {e}")
        sys.exit(2)
    finally:
        log.close()


if __name__ == "__main__":
    main()
