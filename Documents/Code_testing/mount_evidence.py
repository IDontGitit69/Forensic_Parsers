#!/usr/bin/env python3
"""
mount_evidence.py — Forensic Evidence Mass Mounter
====================================================
Recursively discovers and mounts forensic disk images from an evidence
directory tree. Each subdirectory is treated as a separate host/system.

Supported formats
-----------------
  .E01 / .Ex01 / .L01   Expert Witness Format  → ewfmount + losetup + kpartx
  .raw / .img / .dd     Raw disk image         → losetup + kpartx
  .vmdk                 VMware disk            → qemu-nbd + kpartx
  .qcow2 / .qcow        QEMU image             → qemu-nbd + kpartx
  .aff / .afd           AFF image              → affuse + losetup + kpartx

LVM support
-----------
  Partitions containing LVM Physical Volumes are automatically detected.
  The Volume Group is imported under a prefixed name to avoid collisions
  between evidence drives (e.g. two hosts both named "db_vg" → imported
  as "EVIDENCE_host1_db_vg" and "EVIDENCE_host2_db_vg").
  All Logical Volumes in each VG are then mounted under the image mount base.
  udev auto-activation is suppressed during mounting to prevent the OS from
  racing to claim VGs from evidence drives.

Mount layout
------------
  /mnt/IOC_SCAN/
    Hostname1/
      Hostname1_Disk0.E01/
        part1/           ← regular filesystem partition
        part2_lvm/       ← LVM container partition
          lv_root/       ← logical volume mount
          lv_home/
          lv_var/
    Hostname2/
      Hostname2_vmdk0.vmdk/
        part1/

State file
----------
  A JSON state file is written to each image mount base as .mount_state.json
  This enables clean, reliable teardown with --unmount.

Usage
-----
  sudo python3 mount_evidence.py [OPTIONS] <evidence_root>
  sudo python3 mount_evidence.py --unmount [--mount-base /mnt/IOC_SCAN]

Options
-------
  -o, --mount-base DIR   Base mount directory        (default: /mnt/IOC_SCAN)
  -l, --log FILE         Log file                    (default: /var/log/mount_evidence.log)
  -r, --readonly         Read-only mounts            (default: True)
  -w, --readwrite        Read-write (forensically UNSAFE)
  -d, --dry-run          Print actions without executing
  -u, --unmount          Tear down all mounts under mount-base
      --nbd-max N        Override NBD slot count (reload nbd module with nbds_max=N)
  -v, --verbose          Show debug output
  -h, --help             Show this help

Dependencies
------------
  apt install ewf-tools qemu-utils kpartx ntfs-3g util-linux afflib-tools lvm2
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# ── ANSI colours ──────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
CYAN   = "\033[0;36m"

# ── Supported extensions ───────────────────────────────────────────────────────
EWF_FIRST_EXTS   = {".e01", ".ex01", ".l01", ".s01"}
EWF_SEGMENT_PAT  = re.compile(r"^\.(e|ex|l|s)\d{2,}$", re.IGNORECASE)
RAW_EXTS         = {".raw", ".img", ".dd", ".bin"}
VMDK_EXTS        = {".vmdk"}
QCOW_EXTS        = {".qcow2", ".qcow"}
AFF_EXTS         = {".aff", ".afd", ".afm"}
ALL_EXTS         = EWF_FIRST_EXTS | RAW_EXTS | VMDK_EXTS | QCOW_EXTS | AFF_EXTS

# Partition types that cannot be mounted directly as filesystems.
# LVM2_member is NOT in this list — we handle it via lvm_activate_partition().
# crypto_LUKS would need a key so we skip it with a clear message.
UNMOUNTABLE_FS_TYPES = {
    "swap",                # Linux swap — no filesystem
    "linux_raid_member",   # mdadm RAID component — needs array assembly
    "crypto_LUKS",         # LUKS encrypted — needs decryption key
}

# Per-filesystem mount attempt chains (read-only).
# Each entry is a list of argument lists to try IN ORDER — first success wins.
# This gives us graceful degradation per fs type.
FS_MOUNT_ATTEMPTS_RO: dict[str, list[list[str]]] = {
    "ntfs": [
        # Try ntfs-3g with full forensic options first
        ["-t", "ntfs-3g", "-o", "ro,noatime,windows_names,show_sys_files,streams_interface=windows"],
        # ntfs-3g without the extras (some older versions choke on streams_interface)
        ["-t", "ntfs-3g", "-o", "ro,noatime"],
        # In-kernel ntfs driver (kernel 5.15+)
        ["-t", "ntfs",    "-o", "ro,noatime"],
    ],
    "ntfs-3g": [
        ["-t", "ntfs-3g", "-o", "ro,noatime,windows_names,show_sys_files,streams_interface=windows"],
        ["-t", "ntfs-3g", "-o", "ro,noatime"],
        ["-t", "ntfs",    "-o", "ro,noatime"],
    ],
    "vfat": [
        # codepage/iocharset needed for filenames with special chars
        ["-t", "vfat", "-o", "ro,noatime,codepage=437,iocharset=utf8"],
        ["-t", "vfat", "-o", "ro,noatime"],
        # fat fallback — works for FAT12/16 EFI partitions
        ["-t", "msdos", "-o", "ro,noatime"],
    ],
    "exfat": [
        ["-t", "exfat", "-o", "ro,noatime"],
        # fuse-based exfat (older systems)
        ["-t", "exfat-fuse", "-o", "ro,noatime"],
    ],
    "ext2": [
        ["-t", "ext2", "-o", "ro,noatime"],
    ],
    "ext3": [
        # noload prevents journal replay — critical for forensic integrity
        ["-t", "ext3", "-o", "ro,noatime,noload"],
        ["-t", "ext3", "-o", "ro,noatime"],
        # ext2 driver can read ext3 without journal
        ["-t", "ext2", "-o", "ro,noatime"],
    ],
    "ext4": [
        ["-t", "ext4", "-o", "ro,noatime,noload"],
        ["-t", "ext4", "-o", "ro,noatime"],
        # ext2 can read ext4 without journal (loses some features but works)
        ["-t", "ext2", "-o", "ro,noatime"],
    ],
    "xfs": [
        # norecovery prevents log replay — forensically safe
        ["-t", "xfs", "-o", "ro,noatime,norecovery"],
        ["-t", "xfs", "-o", "ro,noatime"],
    ],
    "btrfs": [
        ["-t", "btrfs", "-o", "ro,noatime"],
    ],
    "hfsplus": [
        # force needed for uncleanly unmounted HFS+ (very common on seized devices)
        ["-t", "hfsplus", "-o", "ro,noatime,force"],
        ["-t", "hfsplus", "-o", "ro,noatime"],
    ],
    "hfs": [
        ["-t", "hfs", "-o", "ro,noatime"],
    ],
    "udf": [
        ["-t", "udf", "-o", "ro,noatime"],
    ],
    "iso9660": [
        ["-t", "iso9660", "-o", "ro,noatime"],
    ],
    "squashfs": [
        ["-t", "squashfs", "-o", "ro,noatime"],
    ],
    "f2fs": [
        ["-t", "f2fs", "-o", "ro,noatime"],
    ],
    "erofs": [
        ["-t", "erofs", "-o", "ro,noatime"],
    ],
    "apfs": [
        # apfs-fuse (third-party, rarely installed)
        ["-t", "apfs", "-o", "ro,noatime"],
    ],
}

FS_MOUNT_ATTEMPTS_RW: dict[str, list[list[str]]] = {
    "ntfs":    [["-t", "ntfs-3g", "-o", "rw,noatime,windows_names,show_sys_files"]],
    "ntfs-3g": [["-t", "ntfs-3g", "-o", "rw,noatime,windows_names,show_sys_files"]],
    "vfat":    [["-t", "vfat",    "-o", "rw,noatime,codepage=437,iocharset=utf8"],
                ["-t", "vfat",    "-o", "rw,noatime"]],
    "exfat":   [["-t", "exfat",   "-o", "rw,noatime"]],
    "ext2":    [["-t", "ext2",    "-o", "rw,noatime"]],
    "ext3":    [["-t", "ext3",    "-o", "rw,noatime"]],
    "ext4":    [["-t", "ext4",    "-o", "rw,noatime"]],
    "xfs":     [["-t", "xfs",     "-o", "rw,noatime"]],
    "btrfs":   [["-t", "btrfs",   "-o", "rw,noatime"]],
    "hfsplus": [["-t", "hfsplus", "-o", "rw,noatime,force"],
                ["-t", "hfsplus", "-o", "rw,noatime"]],
    "hfs":     [["-t", "hfs",     "-o", "rw,noatime"]],
}

STATE_FILE = ".mount_state.json"


# ── Logging setup ──────────────────────────────────────────────────────────────

class ColouredFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: RED + BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelno, RESET)
        level  = f"{colour}[{record.levelname[:4]}]{RESET}"
        return f"{level} {record.getMessage()}"


def setup_logging(log_file: str, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("mount_evidence")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(ColouredFormatter())
    logger.addHandler(ch)

    # File handler
    try:
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write to log file {log_file} — file logging disabled")

    return logger


# ── State tracking ─────────────────────────────────────────────────────────────

@dataclass
class MountState:
    """Persisted per-image mount state for reliable teardown."""
    image_path:        str = ""
    mount_base:        str = ""
    loop_devices:      list[str] = field(default_factory=list)
    nbd_devices:       list[str] = field(default_factory=list)
    fuse_mounts:       list[str] = field(default_factory=list)
    partitions:        list[str] = field(default_factory=list)  # mounted fs paths
    lvm_volume_groups: list[str] = field(default_factory=list)  # imported VG names

    def save(self) -> None:
        path = Path(self.mount_base) / STATE_FILE
        try:
            path.write_text(json.dumps(asdict(self), indent=2))
        except Exception as e:
            log.warning(f"Could not write state file {path}: {e}")

    @classmethod
    def load(cls, mount_base: str) -> Optional["MountState"]:
        path = Path(mount_base) / STATE_FILE
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return cls(**data)
        except Exception:
            return None


# ── Subprocess helpers ─────────────────────────────────────────────────────────

log: logging.Logger  # set in main()


def run(cmd: list[str], *, dry_run: bool = False, check: bool = True,
        capture: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run a command with consistent logging and error handling."""
    log.debug(f"CMD: {' '.join(str(c) for c in cmd)}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} {' '.join(str(c) for c in cmd)}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        if result.stdout and log.isEnabledFor(logging.DEBUG):
            for line in result.stdout.strip().splitlines():
                log.debug(f"  stdout: {line}")
        return result
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        raise RuntimeError(f"Command failed (rc={e.returncode}): {' '.join(str(c) for c in cmd)}"
                           + (f"\n  stderr: {stderr}" if stderr else ""))
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out after {timeout}s: {' '.join(str(c) for c in cmd)}")
    except FileNotFoundError:
        raise RuntimeError(f"Executable not found: {cmd[0]}")


def cmd_output(cmd: list[str]) -> str:
    """Run a command and return stripped stdout, empty string on failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception:
        return ""


# ── Dependency checker ─────────────────────────────────────────────────────────

def check_deps() -> None:
    required = ["losetup", "kpartx", "blkid"]
    optional = {
        "ewfmount":       "E01/EWF images (apt install ewf-tools)",
        "qemu-nbd":       "VMDK/QCOW2 images (apt install qemu-utils)",
        "affuse":         "AFF images (apt install afflib-tools)",
        "ntfs-3g":        "NTFS filesystems (apt install ntfs-3g)",
        "fusermount":     "FUSE unmounting (apt install fuse)",
        "vgimportclone":  "LVM volume groups (apt install lvm2)",
        "pvs":            "LVM PV detection (apt install lvm2)",
        "dmsetup":        "Device mapper cleanup (apt install dmsetup)",
    }

    missing_required = [t for t in required if not shutil.which(t)]
    if missing_required:
        log.error(f"Missing required tools: {', '.join(missing_required)}")
        log.error("Install with: sudo apt install util-linux kpartx")
        sys.exit(1)

    for tool, purpose in optional.items():
        if not shutil.which(tool):
            log.warning(f"Optional tool '{tool}' not found — needed for {purpose}")


# ── NBD helpers ────────────────────────────────────────────────────────────────
#
# NBD slots are a finite kernel resource — /dev/nbd0 through /dev/nbd15 by
# default (16 total). Each connected qemu-nbd process holds one slot until
# explicitly disconnected. Slots are NOT released by unmounting partitions —
# you must call `qemu-nbd --disconnect` AND wait for the kernel to confirm
# the slot is free before it can be reused.
#
# Common failure modes:
#   • find_free_nbd() returns a slot that looks free in /sys but the kernel
#     hasn't finished releasing it yet after a recent disconnect → connect fails
#   • --unmount doesn't wait for disconnect to complete → slots leak across runs
#   • More than 16 VMDKs in one session → run out of slots entirely
#
# We handle all three with:
#   1. nbd_is_free()    — multi-signal check (pid + size + qemu process)
#   2. nbd_disconnect() — disconnect + poll until actually free (with timeout)
#   3. nbd_get_max()    — read real slot count from module, warn if insufficient
# ──────────────────────────────────────────────────────────────────────────────

NBD_SETTLE_TIMEOUT = 15   # seconds to wait for a slot to become free
NBD_SETTLE_POLL    = 0.5  # polling interval in seconds


def load_nbd_module() -> int:
    """
    Ensure the nbd kernel module is loaded.
    Returns the number of available NBD slots (nbds_max parameter).

    NOTE: max_part=0 is intentional. Setting max_part>0 makes the kernel
    auto-create /dev/nbdXpY partition devices, duplicating what kpartx creates
    in /dev/mapper/. LVM sees both sets as separate PVs and reports duplicate
    devices, refusing to activate. kpartx handles all partition mapping.
    """
    try:
        run(["modprobe", "nbd", "max_part=0"], check=True, capture=True)
        time.sleep(0.5)
    except Exception as e:
        log.warning(f"Could not load nbd module: {e}")

    return nbd_get_max()


def nbd_get_max() -> int:
    """
    Read the actual nbds_max value from the loaded nbd module.
    Falls back to 16 if the sysfs path is unavailable.
    """
    param_path = Path("/sys/module/nbd/parameters/nbds_max")
    try:
        val = int(param_path.read_text().strip())
        log.debug(f"  NBD slots available: {val}")
        return val
    except Exception:
        return 16


def nbd_is_free(index: int) -> bool:
    """
    Return True only if /dev/nbd<index> is genuinely free.

    Checks three signals — all must be clear:
      1. /sys/block/nbdX/pid does not exist (no qemu-nbd process attached)
      2. /sys/block/nbdX/size reads 0 (no image connected)
      3. No running qemu-nbd process references /dev/nbdX in its cmdline
    """
    dev_name = f"nbd{index}"
    dev_path = f"/dev/{dev_name}"

    # Signal 1: pid sysfs file must not exist
    if Path(f"/sys/block/{dev_name}/pid").exists():
        return False

    # Signal 2: size must be 0
    size_path = Path(f"/sys/block/{dev_name}/size")
    try:
        if int(size_path.read_text().strip()) != 0:
            return False
    except Exception:
        pass  # if we can't read it, be optimistic

    # Signal 3: no qemu-nbd process holding this device
    # Check /proc/*/cmdline for any process referencing this device path
    try:
        proc_dir = Path("/proc")
        for pid_dir in proc_dir.iterdir():
            if not pid_dir.name.isdigit():
                continue
            cmdline_path = pid_dir / "cmdline"
            try:
                cmdline = cmdline_path.read_bytes().replace(b"\x00", b" ").decode(errors="ignore")
                if dev_path in cmdline and "qemu-nbd" in cmdline:
                    return False
            except Exception:
                continue
    except Exception:
        pass

    return True


def find_free_nbd() -> Optional[str]:
    """
    Return the path to a genuinely free /dev/nbdX device.
    Uses nbd_is_free() for a thorough check rather than just looking at pid.
    Logs a warning if slots are running low (≤2 remaining).
    """
    max_slots = nbd_get_max()
    free_slots = []

    for i in range(max_slots):
        dev = f"/dev/nbd{i}"
        if not Path(dev).exists():
            continue
        if nbd_is_free(i):
            free_slots.append((i, dev))

    if not free_slots:
        log.error(
            f"All {max_slots} NBD slots are in use. "
            f"Run with --unmount first, or increase slots: "
            f"rmmod nbd && modprobe nbd nbds_max=32"
        )
        return None

    if len(free_slots) <= 2:
        log.warning(
            f"Only {len(free_slots)} NBD slot(s) remaining out of {max_slots}. "
            f"Consider --unmount between batches or increase nbds_max."
        )

    chosen_idx, chosen_dev = free_slots[0]
    log.debug(f"  Allocated NBD slot: {chosen_dev} ({len(free_slots)-1} remaining after this)")
    return chosen_dev


def nbd_disconnect(dev: str, dry_run: bool = False) -> bool:
    """
    Disconnect a qemu-nbd device and wait until the kernel confirms it is free.

    Returns True if the device is free after the operation, False on timeout.

    Why the wait loop is necessary:
      qemu-nbd --disconnect returns immediately after sending the disconnect
      ioctl, but the kernel releases the slot asynchronously. If you try to
      reconnect (or check the slot) before the kernel finishes, it appears
      busy and the next connect fails with "device busy".
    """
    if dry_run:
        log.info(f"  [DRY-RUN] qemu-nbd --disconnect {dev}")
        return True

    log.info(f"  Disconnecting NBD: {dev}")

    # First remove kpartx mappings so the device isn't busy
    kpartx_remove(dev)
    time.sleep(0.3)

    # Issue the disconnect
    try:
        run(["qemu-nbd", "--disconnect", dev], check=False, capture=True, timeout=10)
    except Exception as e:
        log.warning(f"  qemu-nbd --disconnect returned error for {dev}: {e}")

    # Extract the index number from /dev/nbdX
    try:
        index = int(re.search(r"\d+$", dev).group())
    except Exception:
        log.warning(f"  Could not parse NBD index from {dev}")
        return False

    # Poll until the kernel confirms the slot is free
    deadline = time.monotonic() + NBD_SETTLE_TIMEOUT
    while time.monotonic() < deadline:
        if nbd_is_free(index):
            log.info(f"  NBD slot {dev} confirmed free")
            return True
        time.sleep(NBD_SETTLE_POLL)

    log.warning(
        f"  NBD slot {dev} still appears busy after {NBD_SETTLE_TIMEOUT}s — "
        f"it may release on its own. If problems persist: "
        f"sudo rmmod nbd && sudo modprobe nbd max_part=16"
    )
    return False


# ── losetup helpers ────────────────────────────────────────────────────────────

def losetup_attach(image_path: str, readonly: bool = True) -> str:
    """
    Attach an image file as a loop device. Returns the device path.

    NOTE: --partscan is intentionally NOT used here. It would make the kernel
    auto-create /dev/loopXpY partition devices at the same time kpartx creates
    /dev/mapper/loopXpY — two sets of devices pointing at the same partitions.
    LVM sees this as duplicate PVs and refuses to activate. kpartx is our sole
    partition mapper; losetup just attaches the raw image as a block device.
    """
    cmd = ["losetup", "--find", "--show"]
    if readonly:
        cmd.append("--read-only")
    cmd.append(image_path)
    result = run(cmd, capture=True)
    dev = result.stdout.strip()
    if not dev:
        raise RuntimeError(f"losetup returned empty device for {image_path}")
    log.debug(f"  Loop device: {dev}")
    return dev


def losetup_detach(dev: str) -> None:
    try:
        run(["losetup", "-d", dev], check=True, capture=True)
        log.info(f"  Detached loop device: {dev}")
    except Exception as e:
        log.warning(f"  Failed to detach {dev}: {e}")


# ── kpartx helpers ────────────────────────────────────────────────────────────

def kpartx_add(dev: str, dry_run: bool = False) -> list[str]:
    """
    Map partitions on a block device via kpartx.
    Returns list of /dev/mapper/... partition device paths.
    """
    run(["kpartx", "-asv", dev], dry_run=dry_run, check=False, capture=True)
    time.sleep(0.5)  # allow udev to settle

    if dry_run:
        return [f"/dev/mapper/{Path(dev).name}p1_DRYRUN"]

    dev_name = Path(dev).name  # e.g. "loop0" or "nbd0"
    parts = sorted(glob.glob(f"/dev/mapper/{dev_name}p*"))
    log.debug(f"  kpartx mapped partitions: {parts}")
    return parts


def kpartx_remove(dev: str) -> None:
    try:
        run(["kpartx", "-d", dev], check=False, capture=True)
        log.info(f"  Removed kpartx mappings for: {dev}")
    except Exception as e:
        log.warning(f"  kpartx remove failed for {dev}: {e}")


# ── blkid helpers ─────────────────────────────────────────────────────────────

def blkid_info(dev: str) -> dict[str, str]:
    """
    Return a dict of blkid key=value pairs for a device.
    Keys include TYPE, PART_ENTRY_TYPE, LABEL, UUID, PTTYPE, etc.
    """
    out = cmd_output(["blkid", "-o", "export", dev])
    info: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip()
    return info


def detect_fs(dev: str) -> str:
    """Return the filesystem type on a device, or empty string if unknown."""
    info = blkid_info(dev)
    return info.get("TYPE", "").lower()


def describe_partition(dev: str) -> str:
    """Return a human-readable description of a partition for logging."""
    info = blkid_info(dev)
    parts = []
    if info.get("TYPE"):
        parts.append(info["TYPE"])
    if info.get("LABEL"):
        parts.append(f'label="{info["LABEL"]}"')
    if info.get("UUID"):
        parts.append(f'uuid={info["UUID"][:8]}...')
    if info.get("PART_ENTRY_TYPE"):
        parts.append(f'parttype={info["PART_ENTRY_TYPE"]}')
    return ", ".join(parts) if parts else "unknown"


# ── LVM helpers ───────────────────────────────────────────────────────────────
#
# Proven manual sequence that works:
#   Mount:    vgchange -ay          → activates all VGs on device
#             mount -o ro /dev/mapper/<vg>-<lv> <mountpoint>
#   Teardown: umount <mountpoint>
#             vgchange -an          → deactivates all VGs
#             qemu-nbd --disconnect / losetup -d
#
# We follow this exactly — no vgimportclone, no renaming, no udev tricks.
# ──────────────────────────────────────────────────────────────────────────────

def lvm_activate_all(dry_run: bool) -> bool:
    """Run vgchange -ay to activate all available Volume Groups."""
    if not shutil.which("vgchange"):
        log.warning("  vgchange not found — install lvm2: apt install lvm2")
        return False
    try:
        run(["vgchange", "-ay"], dry_run=dry_run, check=True, capture=True)
        log.info("  LVM: activated all volume groups (vgchange -ay)")
        return True
    except RuntimeError as e:
        log.error(f"  vgchange -ay failed: {e}")
        return False


def lvm_deactivate_all(dry_run: bool) -> None:
    """Run vgchange -an to deactivate all Volume Groups."""
    if not shutil.which("vgchange"):
        return
    try:
        run(["vgchange", "-an"], dry_run=dry_run, check=False, capture=True)
        log.info("  LVM: deactivated all volume groups (vgchange -an)")
    except Exception as e:
        log.warning(f"  vgchange -an failed: {e}")


def lvm_list_active_lvs() -> list[str]:
    """
    Return device paths for all currently active Logical Volumes.
    Reads /dev/mapper/ for entries that look like LVM LVs (contain a dash
    that was originally a double-dash separator: vg--name-lv--name).
    Also checks /dev/<vg>/<lv> paths via lvs output.
    """
    lvs = []

    # Method 1: ask lvs directly — most reliable
    if shutil.which("lvs"):
        out = cmd_output([
            "lvs", "--noheadings", "--readonly",
            "-o", "vg_name,lv_name",
        ])
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) == 2:
                vg, lv = parts
                dev = f"/dev/{vg}/{lv}"
                if Path(dev).exists():
                    lvs.append(dev)

    return lvs


def lvm_mount_active_lvs(mp_base: Path, part_label: str, readonly: bool,
                          state: MountState, dry_run: bool) -> int:
    """
    After vgchange -ay, find all active LVs and mount them under
    mp_base/<part_label>_lvm/<vg_name>/<lv_name>/

    Returns number of LVs successfully mounted.
    """
    lv_devs = lvm_list_active_lvs() if not dry_run else ["/dev/ubuntu-vg/root_DRYRUN"]

    if not lv_devs:
        log.warning("  No active LVs found after vgchange -ay")
        return 0

    log.info(f"  Found {len(lv_devs)} active logical volume(s)")
    lvm_base = mp_base / f"{part_label}_lvm"
    lvm_base.mkdir(parents=True, exist_ok=True)

    mounted = 0
    for lv_dev in lv_devs:
        # Build a clean mount point from the LV path
        # /dev/ubuntu-vg/root → lvm_base/ubuntu-vg/root
        rel = Path(lv_dev).relative_to("/dev")
        lv_mp = lvm_base / rel
        lv_mp.mkdir(parents=True, exist_ok=True)

        fs = detect_fs(lv_dev) if not dry_run else "ext4"
        log.info(f"    Mounting LV {lv_dev} [{fs or 'unknown'}] → {lv_mp}")

        if fs in UNMOUNTABLE_FS_TYPES:
            log.warning(f"    Skipping {lv_dev} — '{fs}' is not mountable")
            try:
                lv_mp.rmdir()
            except Exception:
                pass
            continue

        if _do_mount(lv_dev, lv_mp, fs, readonly, dry_run):
            state.partitions.append(str(lv_mp))
            state.lvm_volume_groups.append(lv_dev)  # track for teardown
            mounted += 1
        else:
            try:
                lv_mp.rmdir()
            except Exception:
                pass

    if mounted == 0:
        try:
            lvm_base.rmdir()
        except Exception:
            pass

    return mounted


def dmsetup_remove_all(dry_run: bool) -> None:
    """
    Remove all non-kpartx device mapper entries.
    Mirrors the manual command that worked:
      dmsetup ls | grep -v "^control" | awk '{print $1}' |
        while read name; do dmsetup remove "$name"; done

    Only removes entries that are NOT kpartx partition maps (loopXpY / nbdXpY).
    kpartx maps look like: loop14p1, nbd0p2 — we leave those for kpartx -d.
    """
    if not shutil.which("dmsetup"):
        return

    out = cmd_output(["dmsetup", "ls"])
    if not out:
        return

    kpartx_pat = re.compile(r"^(loop|nbd)\d+p\d+$")
    entries = []
    for line in out.splitlines():
        cols = line.split()
        if not cols:
            continue
        name = cols[0]
        if name == "control":
            continue
        if kpartx_pat.match(name):
            continue  # leave kpartx maps for kpartx -d
        entries.append(name)

    if not entries:
        log.debug("  No LVM dm entries to remove")
        return

    log.info(f"  Removing {len(entries)} device mapper entries via dmsetup...")
    for name in entries:
        log.info(f"    dmsetup remove --force {name}")
        try:
            run(["dmsetup", "remove", "--force", name],
                dry_run=dry_run, check=False, capture=True)
            time.sleep(0.1)
        except Exception as e:
            log.warning(f"    Failed: {e}")

def mount_partitions(blk_dev: str, mp_base: Path, readonly: bool,
                     state: MountState, dry_run: bool) -> int:
    """
    Enumerate and mount ALL partitions on blk_dev under mp_base.
    Returns number of successfully mounted partitions/volumes.

    Strategy:
      1. Run kpartx to map partition table entries → /dev/mapper/loopXpY
      2. For each mapped partition:
         a. Use blkid to detect filesystem type and partition metadata
         b. If LVM2_member → hand off to lvm_activate_partition()
         c. Skip truly unmountable types (swap, LUKS, RAID)
         d. Otherwise try mount option chain, most-specific to generic
      3. If kpartx finds no partitions, attempt direct mount of the device.
    """
    log.info(f"  Mapping partitions on {blk_dev}")
    parts = kpartx_add(blk_dev, dry_run=dry_run)

    if not parts:
        log.warning(f"  No partition table on {blk_dev} — attempting direct mount")
        fs = detect_fs(blk_dev) if not dry_run else "ext4"
        mp = mp_base / "volume"
        mp.mkdir(parents=True, exist_ok=True)
        if _do_mount(blk_dev, mp, fs, readonly, dry_run):
            state.partitions.append(str(mp))
            return 1
        else:
            try:
                mp.rmdir()
            except Exception:
                pass
            log.error(f"  Could not mount {blk_dev} — no filesystem detected")
            return 0

    mounted = 0
    for i, part in enumerate(parts, start=1):
        part_label = f"part{i}"
        desc = describe_partition(part) if not dry_run else "dry-run"
        log.info(f"  Partition {i}: {part}  [{desc}]")

        if not dry_run:
            info = blkid_info(part)
            fs   = info.get("TYPE", "").lower()

            if info.get("LABEL"):
                log.info(f"    Label : {info['LABEL']}")
            if info.get("UUID"):
                log.info(f"    UUID  : {info['UUID']}")

            # ── LVM Physical Volume ────────────────────────────────────────
            if fs == "lvm2_member":
                log.info(f"    LVM Physical Volume detected on {part} — running vgchange -ay")
                if lvm_activate_all(dry_run):
                    time.sleep(1)  # give kernel time to create /dev/mapper LV entries
                    n = lvm_mount_active_lvs(mp_base, part_label, readonly, state, dry_run)
                    mounted += n
                else:
                    log.error(f"    vgchange -ay failed — LVM volumes on {part} not mounted")
                continue

            # ── Truly unmountable ──────────────────────────────────────────
            if fs in UNMOUNTABLE_FS_TYPES:
                log.warning(f"    Skipping {part} — '{fs}' cannot be mounted")
                if fs == "crypto_luks":
                    log.warning(f"    (LUKS encrypted — decryption key required)")
                continue
        else:
            fs = "ext4"

        # ── Regular filesystem ─────────────────────────────────────────────
        mp = mp_base / part_label
        mp.mkdir(parents=True, exist_ok=True)

        if _do_mount(part, mp, fs, readonly, dry_run):
            state.partitions.append(str(mp))
            mounted += 1
        else:
            try:
                mp.rmdir()
            except Exception:
                pass

    return mounted


def _do_mount(dev: str, mp: Path, fs: str, readonly: bool, dry_run: bool) -> bool:
    """
    Attempt to mount dev at mp using a progressive chain of strategies.

    Mount attempt order:
      1. fs-specific options (e.g. ntfs-3g with forensic flags, noload for ext4)
      2. fs-specific fallbacks (e.g. drop noload, try alternate driver)
      3. Generic ro/rw with just noatime (let kernel auto-detect)
      4. Bare mount with no options at all (last resort)

    This means even an EFI/FAT12 partition that blkid called 'vfat' but the
    kernel calls 'msdos' will still mount on attempt 3 or 4.
    """
    ro_rw = "ro" if readonly else "rw"
    attempts_map = FS_MOUNT_ATTEMPTS_RO if readonly else FS_MOUNT_ATTEMPTS_RW

    # Build the attempt chain
    attempts: list[tuple[str, list[str]]] = []

    # 1+2. fs-specific chains
    if fs and fs in attempts_map:
        for opts in attempts_map[fs]:
            attempts.append((f"fs-specific ({fs})", ["mount"] + opts + [dev, str(mp)]))

    # 3. Generic — let the kernel figure out the filesystem
    attempts.append(("generic", ["mount", "-o", f"{ro_rw},noatime", dev, str(mp)]))

    # 4. Bare mount — absolute last resort
    attempts.append(("bare", ["mount", dev, str(mp)]))

    for label, cmd in attempts:
        try:
            run(cmd, dry_run=dry_run, check=True, capture=True)
            fs_label = fs if fs else "auto-detected"
            log.info(f"    ✓ Mounted ({label}) [{fs_label}] → {mp}")
            return True
        except RuntimeError as e:
            log.debug(f"    Attempt '{label}' failed: {e}")

    log.error(f"    ✗ All mount attempts exhausted for {dev} (fs={fs or 'unknown'})")
    return False


# ── Format-specific mounters ──────────────────────────────────────────────────

def mount_raw(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    """Mount a raw/img/dd image."""
    log.info(f"Mounting RAW image: {img}")
    try:
        loop_dev = losetup_attach(str(img), readonly=readonly) if not dry_run \
                   else "/dev/loop_DRYRUN"
        state.loop_devices.append(loop_dev)
        n = mount_partitions(loop_dev, mp_base, readonly, state, dry_run)
        return n > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  RAW mount failed: {e}")
        return False


def mount_ewf(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    """Mount an EWF (E01/Ex01/L01) image via ewfmount."""
    if not shutil.which("ewfmount"):
        log.error("ewfmount not found — install: sudo apt install ewf-tools")
        return False

    log.info(f"Mounting EWF image: {img}")

    fuse_mp = mp_base / ".ewf_fuse"
    fuse_mp.mkdir(parents=True, exist_ok=True)

    try:
        run(["ewfmount", str(img), str(fuse_mp)],
            dry_run=dry_run, check=True, capture=True)
        state.fuse_mounts.append(str(fuse_mp))
    except RuntimeError as e:
        log.error(f"  ewfmount failed: {e}")
        try:
            fuse_mp.rmdir()
        except Exception:
            pass
        return False

    raw_file = fuse_mp / "ewf1"
    if not dry_run and not raw_file.exists():
        candidates = list(fuse_mp.iterdir())
        if candidates:
            raw_file = candidates[0]
            log.debug(f"  ewf raw file detected as: {raw_file}")
        else:
            log.error(f"  ewfmount succeeded but no raw file found in {fuse_mp}")
            return False

    try:
        loop_dev = losetup_attach(str(raw_file), readonly=readonly) if not dry_run \
                   else "/dev/loop_DRYRUN"
        state.loop_devices.append(loop_dev)
        n = mount_partitions(loop_dev, mp_base, readonly, state, dry_run)
        return n > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  EWF loop/partition mount failed: {e}")
        return False


def _nbd_connect(img: Path, readonly: bool, state: MountState,
                 dry_run: bool, label: str) -> Optional[str]:
    """
    Shared NBD connect logic for VMDK and QCOW2.
    Finds a free slot, connects qemu-nbd, verifies the connection by checking
    that the device size is non-zero, and records the device in state.
    Returns the nbd device path on success, None on failure.
    """
    load_nbd_module()

    nbd_dev = find_free_nbd() if not dry_run else "/dev/nbd_DRYRUN"
    if not nbd_dev:
        return None

    ro_flag = ["--read-only"] if readonly else []
    try:
        run(["qemu-nbd", "--connect", nbd_dev] + ro_flag + [str(img)],
            dry_run=dry_run, check=True, capture=True, timeout=30)
    except RuntimeError as e:
        log.error(f"  qemu-nbd connect failed for {label}: {e}")
        return None

    if not dry_run:
        # Verify the device actually connected by polling size
        # qemu-nbd returns before the kernel has fully set up the device
        index = int(re.search(r"\d+$", nbd_dev).group())
        size_path = Path(f"/sys/block/nbd{index}/size")
        deadline = time.monotonic() + 10
        connected = False
        while time.monotonic() < deadline:
            try:
                if int(size_path.read_text().strip()) > 0:
                    connected = True
                    break
            except Exception:
                pass
            time.sleep(0.25)

        if not connected:
            log.error(f"  qemu-nbd connected to {nbd_dev} but device size is 0 — image may be corrupt or unsupported")
            # Clean up the bad connection
            try:
                run(["qemu-nbd", "--disconnect", nbd_dev], check=False, capture=True, timeout=10)
            except Exception:
                pass
            return None

        log.debug(f"  {label} connected to {nbd_dev} (verified non-zero size)")

    state.nbd_devices.append(nbd_dev)
    return nbd_dev


def mount_vmdk(img: Path, mp_base: Path, readonly: bool,
               state: MountState, dry_run: bool) -> bool:
    """Mount a VMDK image via qemu-nbd."""
    if not shutil.which("qemu-nbd"):
        log.error("qemu-nbd not found — install: sudo apt install qemu-utils")
        return False

    log.info(f"Mounting VMDK image: {img}")

    nbd_dev = _nbd_connect(img, readonly, state, dry_run, label=img.name)
    if not nbd_dev:
        return False

    try:
        n = mount_partitions(nbd_dev, mp_base, readonly, state, dry_run)
        return n > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  VMDK partition mount failed: {e}")
        return False


def mount_qcow2(img: Path, mp_base: Path, readonly: bool,
                state: MountState, dry_run: bool) -> bool:
    """Mount a QCOW2 image via qemu-nbd."""
    if not shutil.which("qemu-nbd"):
        log.error("qemu-nbd not found — install: sudo apt install qemu-utils")
        return False

    log.info(f"Mounting QCOW2 image: {img}")

    nbd_dev = _nbd_connect(img, readonly, state, dry_run, label=img.name)
    if not nbd_dev:
        return False

    try:
        n = mount_partitions(nbd_dev, mp_base, readonly, state, dry_run)
        return n > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  QCOW2 partition mount failed: {e}")
        return False


def mount_aff(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    """Mount an AFF image via affuse."""
    if not shutil.which("affuse"):
        log.error("affuse not found — install: sudo apt install afflib-tools")
        return False

    log.info(f"Mounting AFF image: {img}")

    fuse_mp = mp_base / ".aff_fuse"
    fuse_mp.mkdir(parents=True, exist_ok=True)

    try:
        run(["affuse", str(img), str(fuse_mp)],
            dry_run=dry_run, check=True, capture=True)
        state.fuse_mounts.append(str(fuse_mp))
    except RuntimeError as e:
        log.error(f"  affuse failed: {e}")
        try:
            fuse_mp.rmdir()
        except Exception:
            pass
        return False

    raw_file = fuse_mp / f"{img.name}.raw"
    if not dry_run and not raw_file.exists():
        candidates = [f for f in fuse_mp.iterdir() if f.suffix == ".raw"]
        if candidates:
            raw_file = candidates[0]
        else:
            log.error(f"  affuse succeeded but no .raw file found in {fuse_mp}")
            return False

    try:
        loop_dev = losetup_attach(str(raw_file), readonly=readonly) if not dry_run \
                   else "/dev/loop_DRYRUN"
        state.loop_devices.append(loop_dev)
        n = mount_partitions(loop_dev, mp_base, readonly, state, dry_run)
        return n > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  AFF loop/partition mount failed: {e}")
        return False


# ── Image dispatcher ───────────────────────────────────────────────────────────

MOUNTERS = {
    **{ext: mount_ewf   for ext in EWF_FIRST_EXTS},
    **{ext: mount_raw   for ext in RAW_EXTS},
    **{ext: mount_vmdk  for ext in VMDK_EXTS},
    **{ext: mount_qcow2 for ext in QCOW_EXTS},
    **{ext: mount_aff   for ext in AFF_EXTS},
}


def sanitise(name: str) -> str:
    """Replace spaces with underscores and strip non-safe characters."""
    return re.sub(r"[^\w.\-]", "_", name.replace(" ", "_"))


def is_ewf_segment(ext: str) -> bool:
    """Return True if this extension is a non-first EWF segment (.E02, .E03 …)"""
    ext_l = ext.lower()
    if EWF_SEGMENT_PAT.match(ext_l) and ext_l not in EWF_FIRST_EXTS:
        return True
    return False


def process_image(img_path: Path, hostname: str, label: str,
                  mount_base: Path, readonly: bool, dry_run: bool) -> bool:
    """Dispatch a single image file to the appropriate mounter."""
    ext = img_path.suffix.lower()
    mounter = MOUNTERS.get(ext)

    mp_base = mount_base / hostname / label
    mp_base.mkdir(parents=True, exist_ok=True)

    state = MountState(
        image_path=str(img_path),
        mount_base=str(mp_base),
    )

    if mounter is None:
        log.warning(f"Unrecognised extension '{ext}' — attempting raw mount")
        mounter = mount_raw

    ok = mounter(img_path, mp_base, readonly, state, dry_run)
    state.save()

    if not ok:
        log.error(f"Failed to mount: {img_path}")
        try:
            if mp_base.exists() and not any(mp_base.iterdir()):
                mp_base.rmdir()
        except Exception:
            pass

    return ok


# ── Discovery ─────────────────────────────────────────────────────────────────

def discover_images(evidence_root: Path) -> list[tuple[Path, str, str]]:
    """
    Walk evidence_root and return a list of (image_path, hostname, label).

    Directory structure expected:
        evidence_root/
          <Hostname>/
            <image files>
    """
    results: list[tuple[Path, str, str]] = []
    seen_labels: dict[str, set[str]] = {}  # hostname → set of labels used

    all_files = sorted(evidence_root.rglob("*"))

    for f in all_files:
        if not f.is_file():
            continue

        ext = f.suffix.lower()

        # Skip non-image files
        if ext not in ALL_EXTS and not EWF_SEGMENT_PAT.match(ext):
            continue

        # Skip non-first EWF segments
        if is_ewf_segment(ext):
            log.debug(f"Skipping EWF segment: {f}")
            continue

        # Determine hostname from parent directory relative to evidence_root
        rel = f.relative_to(evidence_root)
        parts = rel.parts

        if len(parts) == 1:
            # Image is directly in evidence_root (no subdirectory)
            # Use evidence_root's name as the hostname
            hostname = sanitise(evidence_root.name)
        else:
            # Use the immediate subdirectory name as hostname
            hostname = sanitise(parts[0])

        # Build a clean label from the filename
        base  = sanitise(f.stem)
        label = f"{base}{f.suffix}"

        # Deduplicate labels within the same hostname
        used = seen_labels.setdefault(hostname, set())
        original_label = label
        counter = 1
        while label in used:
            label = f"{sanitise(f.stem)}_{counter}{f.suffix}"
            counter += 1
        used.add(label)

        if label != original_label:
            log.debug(f"Label collision resolved: {original_label} → {label}")

        results.append((f, hostname, label))

    return results


# ── Unmount ────────────────────────────────────────────────────────────────────

def unmount_all(mount_base: Path, dry_run: bool) -> None:
    banner("Unmounting all evidence", str(mount_base))

    if not mount_base.exists():
        log.warning(f"{mount_base} does not exist — nothing to unmount")
        return

    # 1. Collect all state files
    state_files = sorted(mount_base.rglob(STATE_FILE), reverse=True)

    if not state_files:
        log.warning("No .mount_state.json files found — falling back to full teardown")
        _unmount_by_proc(mount_base, dry_run)
        lvm_deactivate_all(dry_run)
        if not dry_run:
            time.sleep(0.5)
        dmsetup_remove_all(dry_run)
        return

    for sf in state_files:
        state = MountState.load(str(sf.parent))
        if state is None:
            continue

        log.info(f"\n── Unmounting: {state.image_path}")

        # Proven teardown order (mirrors what worked manually):
        #   1. umount all filesystem mountpoints (LVs and regular partitions)
        #   2. vgchange -an  (deactivate all VGs — clears /dev/mapper LV entries)
        #   3. dmsetup remove any remaining dm entries (catches udev strays)
        #   4. kpartx -d + losetup -d  (release partition maps and loop device)
        #   5. qemu-nbd --disconnect   (release NBD device, wait for confirmation)
        #   6. umount FUSE mounts      (ewfmount/affuse — deepest layer, last)

        # 1. Unmount all tracked mountpoints (deepest path first)
        for mp in sorted(state.partitions, reverse=True):
            _umount(mp, dry_run)

        if not dry_run:
            time.sleep(0.5)

        # 2. Deactivate all LVM VGs
        if state.lvm_volume_groups:
            lvm_deactivate_all(dry_run)
            if not dry_run:
                time.sleep(0.5)

        # 3. Clean up any remaining dm entries (udev auto-activated strays)
        dmsetup_remove_all(dry_run)

        if not dry_run:
            time.sleep(0.3)

        # 4. kpartx remove + losetup detach
        for dev in state.loop_devices:
            if not dry_run:
                kpartx_remove(dev)
                time.sleep(0.3)
                losetup_detach(dev)
            else:
                log.info(f"  [DRY-RUN] kpartx -d {dev} && losetup -d {dev}")

        # 5. NBD disconnect — polls until kernel confirms free
        for dev in state.nbd_devices:
            nbd_disconnect(dev, dry_run=dry_run)

        # 6. FUSE mounts last
        for mp in state.fuse_mounts:
            _umount(mp, dry_run)

        # e. Remove state file
        if not dry_run:
            try:
                sf.unlink()
            except Exception:
                pass

    # 2. Clean up empty directories
    log.info("Cleaning empty directories…")
    if not dry_run:
        _cleanup_empty_dirs(mount_base)

    banner("Unmount complete")


def _umount(mp: str, dry_run: bool) -> None:
    p = Path(mp)
    if not dry_run and not p.exists():
        return
    try:
        run(["umount", "-l", mp], dry_run=dry_run, check=True, capture=True)
        log.info(f"  Unmounted: {mp}")
    except RuntimeError as e:
        log.warning(f"  umount failed for {mp}: {e}")


def _unmount_by_proc(mount_base: Path, dry_run: bool) -> None:
    """Fallback: scan /proc/mounts for anything under mount_base."""
    mounts = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith(str(mount_base)):
                    mounts.append(parts[1])
    except Exception:
        pass

    for mp in sorted(mounts, reverse=True):
        _umount(mp, dry_run)


def _cleanup_empty_dirs(base: Path) -> None:
    """Remove empty directories bottom-up."""
    for dirpath, dirnames, filenames in os.walk(str(base), topdown=False):
        p = Path(dirpath)
        if p == base:
            continue
        try:
            # Only remove if truly empty (no files, no subdirs)
            if not any(p.iterdir()):
                p.rmdir()
                log.debug(f"  Removed empty dir: {p}")
        except Exception:
            pass


# ── UI helpers ────────────────────────────────────────────────────────────────

def banner(title: str, detail: str = "") -> None:
    line = "═" * 54
    print(f"\n{BOLD}{CYAN}{line}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    if detail:
        print(f"{CYAN}  {detail}{RESET}")
    print(f"{BOLD}{CYAN}{line}{RESET}")


def print_summary(results: list[tuple[str, bool]], mount_base: Path,
                  log_file: str, dry_run: bool) -> None:
    ok     = sum(1 for _, s in results if s)
    failed = sum(1 for _, s in results if not s)
    total  = len(results)

    print(f"\n{BOLD}{'═'*46}{RESET}")
    print(f"{BOLD}  Mount Summary{RESET}")
    print(f"{'─'*46}")
    print(f"  Total images processed : {total}")
    print(f"  {GREEN}Successfully mounted   : {ok}{RESET}")
    if failed:
        print(f"  {RED}Failed                 : {failed}{RESET}")
    else:
        print(f"  Failed                 : {failed}")
    print(f"{'─'*46}")
    print(f"  Mount base : {mount_base}")
    print(f"  Log file   : {log_file}")
    print(f"{BOLD}{'═'*46}{RESET}\n")

    if ok > 0 and not dry_run and mount_base.exists():
        print(f"{CYAN}Mount tree:{RESET}")
        _print_tree(mount_base, prefix="  ", max_depth=4)


def _print_tree(path: Path, prefix: str = "", max_depth: int = 4, depth: int = 0) -> None:
    if depth >= max_depth:
        return
    try:
        entries = sorted(e for e in path.iterdir() if not e.name.startswith("."))
    except PermissionError:
        return
    for i, entry in enumerate(entries):
        connector = "└── " if i == len(entries) - 1 else "├── "
        print(f"{prefix}{connector}{entry.name}")
        if entry.is_dir():
            extension = "    " if i == len(entries) - 1 else "│   "
            _print_tree(entry, prefix + extension, max_depth, depth + 1)


# ── Argument parser ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mount_evidence.py",
        description="Forensic Evidence Mass Mounter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("evidence_root", nargs="?", metavar="EVIDENCE_ROOT",
                   help="Root directory containing host subdirectories with images")
    p.add_argument("-o", "--mount-base", default="/mnt/IOC_SCAN", metavar="DIR",
                   help="Base mount directory (default: /mnt/IOC_SCAN)")
    p.add_argument("-l", "--log", default="/var/log/mount_evidence.log", metavar="FILE",
                   help="Log file path")
    p.add_argument("-r", "--readonly", dest="readonly", action="store_true", default=True,
                   help="Mount read-only (default)")
    p.add_argument("-w", "--readwrite", dest="readonly", action="store_false",
                   help="Mount read-write (forensically UNSAFE)")
    p.add_argument("-d", "--dry-run", action="store_true",
                   help="Print what would be done without doing it")
    p.add_argument("-u", "--unmount", action="store_true",
                   help="Unmount everything under mount-base")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose/debug output")
    p.add_argument("--nbd-max", type=int, default=0, metavar="N",
                   help=(
                       "Override the number of NBD slots by reloading the nbd module "
                       "with nbds_max=N. Default 16 is often too few for VCenter cases "
                       "with 11+ VMDKs. Example: --nbd-max 32. "
                       "Requires no NBD devices currently in use."
                   ))
    return p


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    global log

    parser = build_parser()
    args = parser.parse_args()

    log = setup_logging(args.log, args.verbose)

    # Root check
    if os.geteuid() != 0:
        log.error("This script must be run as root (sudo python3 mount_evidence.py …)")
        return 1

    mount_base = Path(args.mount_base)

    # ── Unmount mode ──────────────────────────────────────────────────────────
    if args.unmount:
        unmount_all(mount_base, args.dry_run)
        return 0

    # ── Mount mode ────────────────────────────────────────────────────────────
    if not args.evidence_root:
        parser.print_help()
        return 1

    evidence_root = Path(args.evidence_root).resolve()
    if not evidence_root.exists():
        log.error(f"Evidence root does not exist: {evidence_root}")
        return 1
    if not evidence_root.is_dir():
        log.error(f"Evidence root is not a directory: {evidence_root}")
        return 1

    check_deps()
    mount_base.mkdir(parents=True, exist_ok=True)

    # Expand NBD slots if requested
    if args.nbd_max > 0:
        current = nbd_get_max()
        if args.nbd_max != current:
            log.info(f"Reloading nbd module with nbds_max={args.nbd_max} (was {current})")
            try:
                run(["rmmod", "nbd"], check=True, capture=True)
                run(["modprobe", "nbd", "max_part=0", f"nbds_max={args.nbd_max}"],
                    check=True, capture=True)
                time.sleep(0.5)
                actual = nbd_get_max()
                log.info(f"NBD slots now: {actual}")
            except RuntimeError as e:
                log.warning(f"Could not reload nbd module: {e} — continuing with {current} slots")
        else:
            log.debug(f"NBD slots already at {current}, --nbd-max {args.nbd_max} is a no-op")

    # Discover images
    images = discover_images(evidence_root)
    if not images:
        log.error(f"No forensic images found under {evidence_root}")
        log.error(f"Supported extensions: {', '.join(sorted(ALL_EXTS))}")
        return 1

    banner(
        "Forensic Evidence Mass Mounter",
        f"Root: {evidence_root}  |  Base: {mount_base}  |  "
        f"Mode: {'READ-ONLY' if args.readonly else 'READ-WRITE ⚠'}  |  "
        f"Images: {len(images)}"
    )

    results: list[tuple[str, bool]] = []

    for img_path, hostname, label in images:
        print(f"\n{BOLD}── {hostname} / {label}{RESET}")
        ok = process_image(
            img_path, hostname, label,
            mount_base, args.readonly, args.dry_run
        )
        results.append((str(img_path), ok))

    print_summary(results, mount_base, args.log, args.dry_run)

    failed = sum(1 for _, ok in results if not ok)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
