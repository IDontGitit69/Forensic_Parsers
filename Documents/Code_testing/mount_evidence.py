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
  .vmdk                 VMware disk            → qemu-nbd (partitions via /dev/nbdXpY)
  .qcow2 / .qcow        QEMU image             → qemu-nbd (partitions via /dev/nbdXpY)
  .aff / .afd           AFF image              → affuse + losetup + kpartx

LVM support
-----------
  When a partition is detected as an LVM2 Physical Volume, the script runs
  vgchange -ay to activate all Volume Groups, then mounts each Logical Volume.
  Teardown runs vgchange -an before disconnecting block devices.

Mount layout
------------
  /mnt/IOC_SCAN/
    Hostname1/
      image.E01/
        part1/           ← EFI / boot
        part2/           ← root filesystem
    Hostname2/
      disk.vmdk/
        part1/           ← regular partition
        part2_lvm/       ← LVM container
          ubuntu--vg/
            ubuntu--lv/  ← logical volume

State file
----------
  .mount_state.json written into each image mount base for reliable teardown.

Usage
-----
  sudo python3 mount_evidence.py [OPTIONS] <evidence_root>
  sudo python3 mount_evidence.py --unmount [--mount-base /mnt/IOC_SCAN]

Options
-------
  -o, --mount-base DIR   Base mount directory   (default: /mnt/IOC_SCAN)
  -l, --log FILE         Log file               (default: /var/log/mount_evidence.log)
  -r, --readonly         Read-only mounts       (default: True)
  -w, --readwrite        Read-write (forensically UNSAFE)
  -d, --dry-run          Print actions, do nothing
  -u, --unmount          Tear down all mounts under mount-base
  -v, --verbose          Debug output
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

# ── Colours ───────────────────────────────────────────────────────────────────
RESET  = "\033[0m";  BOLD  = "\033[1m"
RED    = "\033[0;31m"; GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"; CYAN  = "\033[0;36m"

# ── Supported extensions ───────────────────────────────────────────────────────
EWF_FIRST_EXTS  = {".e01", ".ex01", ".l01", ".s01"}
EWF_SEG_PAT     = re.compile(r"^\.(e|ex|l|s)\d{2,}$", re.IGNORECASE)
RAW_EXTS        = {".raw", ".img", ".dd", ".bin"}
VMDK_EXTS       = {".vmdk"}
QCOW_EXTS       = {".qcow2", ".qcow"}
AFF_EXTS        = {".aff", ".afd", ".afm"}
ALL_EXTS        = EWF_FIRST_EXTS | RAW_EXTS | VMDK_EXTS | QCOW_EXTS | AFF_EXTS

UNMOUNTABLE_FS  = {"swap", "linux_raid_member", "crypto_luks"}

STATE_FILE = ".mount_state.json"

# ── Filesystem mount option chains ────────────────────────────────────────────
# Each fs maps to a list of option-lists tried in order — first success wins.
FS_OPTS_RO: dict[str, list[list[str]]] = {
    "ntfs":    [["-t","ntfs-3g","-o","ro,noatime,windows_names,show_sys_files,streams_interface=windows"],
                ["-t","ntfs-3g","-o","ro,noatime"],
                ["-t","ntfs",   "-o","ro,noatime"]],
    "ntfs-3g": [["-t","ntfs-3g","-o","ro,noatime,windows_names,show_sys_files,streams_interface=windows"],
                ["-t","ntfs-3g","-o","ro,noatime"]],
    "vfat":    [["-t","vfat","-o","ro,noatime,codepage=437,iocharset=utf8"],
                ["-t","vfat","-o","ro,noatime"],
                ["-t","msdos","-o","ro,noatime"]],
    "exfat":   [["-t","exfat","-o","ro,noatime"]],
    "ext2":    [["-t","ext2","-o","ro,noatime"]],
    "ext3":    [["-t","ext3","-o","ro,noatime,noload"],
                ["-t","ext3","-o","ro,noatime"],
                ["-t","ext2","-o","ro,noatime"]],
    "ext4":    [["-t","ext4","-o","ro,noload"],          # always try noload first — works for LVM LVs
                ["-t","ext4","-o","ro,noatime,noload"],
                ["-t","ext4","-o","ro,noatime"],
                ["-t","ext2","-o","ro,noatime"]],
    "xfs":     [["-t","xfs","-o","ro,noatime,norecovery"],
                ["-t","xfs","-o","ro,noatime"]],
    "btrfs":   [["-t","btrfs","-o","ro,noatime"]],
    "hfsplus": [["-t","hfsplus","-o","ro,noatime,force"],
                ["-t","hfsplus","-o","ro,noatime"]],
    "hfs":     [["-t","hfs","-o","ro,noatime"]],
    "udf":     [["-t","udf","-o","ro,noatime"]],
    "iso9660": [["-t","iso9660","-o","ro,noatime"]],
    "squashfs":[["-t","squashfs","-o","ro,noatime"]],
}
FS_OPTS_RW: dict[str, list[list[str]]] = {
    "ntfs":    [["-t","ntfs-3g","-o","rw,noatime,windows_names,show_sys_files"]],
    "ntfs-3g": [["-t","ntfs-3g","-o","rw,noatime,windows_names,show_sys_files"]],
    "vfat":    [["-t","vfat","-o","rw,noatime,codepage=437,iocharset=utf8"],
                ["-t","vfat","-o","rw,noatime"]],
    "exfat":   [["-t","exfat","-o","rw,noatime"]],
    "ext2":    [["-t","ext2","-o","rw,noatime"]],
    "ext3":    [["-t","ext3","-o","rw,noatime"]],
    "ext4":    [["-t","ext4","-o","rw,noatime"]],
    "xfs":     [["-t","xfs", "-o","rw,noatime"]],
    "btrfs":   [["-t","btrfs","-o","rw,noatime"]],
    "hfsplus": [["-t","hfsplus","-o","rw,noatime,force"],
                ["-t","hfsplus","-o","rw,noatime"]],
}


# ── Logging ───────────────────────────────────────────────────────────────────
class ColouredFormatter(logging.Formatter):
    COLOURS = {logging.DEBUG: CYAN, logging.INFO: GREEN,
               logging.WARNING: YELLOW, logging.ERROR: RED}
    def format(self, record):
        c = self.COLOURS.get(record.levelno, RESET)
        return f"{c}[{record.levelname[:4]}]{RESET} {record.getMessage()}"

def setup_logging(log_file: str, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("mount_evidence")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(ColouredFormatter())
    logger.addHandler(ch)
    try:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    except PermissionError:
        logger.warning(f"Cannot write log to {log_file}")
    return logger

log: logging.Logger  # set in main()


# ── State ─────────────────────────────────────────────────────────────────────
@dataclass
class MountState:
    image_path:        str       = ""
    mount_base:        str       = ""
    loop_devices:      list[str] = field(default_factory=list)
    nbd_devices:       list[str] = field(default_factory=list)
    fuse_mounts:       list[str] = field(default_factory=list)
    partitions:        list[str] = field(default_factory=list)
    lvm_volume_groups: list[str] = field(default_factory=list)

    def save(self):
        p = Path(self.mount_base) / STATE_FILE
        try:
            p.write_text(json.dumps(asdict(self), indent=2))
        except Exception as e:
            log.warning(f"Could not save state: {e}")

    @classmethod
    def load(cls, mount_base: str) -> Optional["MountState"]:
        p = Path(mount_base) / STATE_FILE
        if not p.exists():
            return None
        try:
            return cls(**json.loads(p.read_text()))
        except Exception:
            return None


# ── Subprocess ────────────────────────────────────────────────────────────────
def run(cmd: list[str], *, dry_run=False, check=True,
        capture=False, timeout=60) -> subprocess.CompletedProcess:
    log.debug(f"CMD: {' '.join(str(c) for c in cmd)}")
    if dry_run:
        print(f"  {CYAN}[DRY-RUN]{RESET} {' '.join(str(c) for c in cmd)}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    try:
        r = subprocess.run(cmd, check=check, capture_output=capture,
                           text=True, timeout=timeout)
        if r.stdout:
            for line in r.stdout.strip().splitlines():
                log.debug(f"  stdout: {line}")
        return r
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"Command failed (rc={e.returncode}): {' '.join(str(c) for c in cmd)}"
            + (f"\n  stderr: {(e.stderr or '').strip()}" if e.stderr else ""))
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Timed out: {' '.join(str(c) for c in cmd)}")
    except FileNotFoundError:
        raise RuntimeError(f"Not found: {cmd[0]}")

def cmd_out(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.stdout.strip()
    except Exception:
        return ""


# ── Dependency check ──────────────────────────────────────────────────────────
def check_deps():
    for t in ["losetup", "kpartx", "blkid"]:
        if not shutil.which(t):
            log.error(f"Required tool missing: {t}")
            sys.exit(1)
    for t, pkg in [("ewfmount","ewf-tools"), ("qemu-nbd","qemu-utils"),
                   ("affuse","afflib-tools"), ("ntfs-3g","ntfs-3g"),
                   ("vgchange","lvm2"), ("dmsetup","dmsetup")]:
        if not shutil.which(t):
            log.warning(f"Optional tool '{t}' not found (apt install {pkg})")


# ── blkid ─────────────────────────────────────────────────────────────────────
def blkid_info(dev: str) -> dict[str, str]:
    out = cmd_out(["blkid", "-o", "export", dev])
    info: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip()] = v.strip()
    return info

def detect_fs(dev: str) -> str:
    return blkid_info(dev).get("TYPE", "").lower()

def describe_part(dev: str) -> str:
    info = blkid_info(dev)
    parts = []
    if info.get("TYPE"):   parts.append(info["TYPE"])
    if info.get("LABEL"):  parts.append(f'label="{info["LABEL"]}"')
    if info.get("UUID"):   parts.append(f'uuid={info["UUID"][:8]}...')
    return ", ".join(parts) if parts else "unknown"


# ── Mount a single filesystem ─────────────────────────────────────────────────
def do_mount(dev: str, mp: Path, fs: str, readonly: bool, dry_run: bool) -> bool:
    """Try progressively simpler mount options until one works."""
    ro_rw = "ro" if readonly else "rw"
    opts_map = FS_OPTS_RO if readonly else FS_OPTS_RW

    attempts: list[tuple[str, list[str]]] = []
    if fs in opts_map:
        for opts in opts_map[fs]:
            attempts.append((f"{fs}-specific", ["mount"] + opts + [dev, str(mp)]))
    attempts.append(("generic",  ["mount", "-o", f"{ro_rw},noatime", dev, str(mp)]))
    attempts.append(("bare",     ["mount", dev, str(mp)]))

    for label, cmd in attempts:
        try:
            run(cmd, dry_run=dry_run, check=True, capture=True)
            log.info(f"    ✓ Mounted [{label}] {dev} → {mp}")
            return True
        except RuntimeError as e:
            log.debug(f"    attempt '{label}' failed: {e}")

    log.error(f"    ✗ All mount attempts failed for {dev} (fs={fs or 'unknown'})")
    return False


# ── LVM ───────────────────────────────────────────────────────────────────────
def lvm_activate(dry_run: bool) -> bool:
    if not shutil.which("vgchange"):
        log.warning("  vgchange not found — skipping LVM (apt install lvm2)")
        return False
    try:
        run(["vgchange", "-ay"], dry_run=dry_run, check=True, capture=True)
        log.info("  LVM: vgchange -ay — all VGs activated")
        return True
    except RuntimeError as e:
        log.error(f"  vgchange -ay failed: {e}")
        return False

def lvm_deactivate(dry_run: bool):
    if not shutil.which("vgchange"):
        return
    try:
        run(["vgchange", "-an"], dry_run=dry_run, check=False, capture=True)
        log.info("  LVM: vgchange -an — all VGs deactivated")
    except Exception as e:
        log.warning(f"  vgchange -an: {e}")

def lvm_active_lvs() -> list[str]:
    """Return /dev/<vg>/<lv> paths for every currently active LV."""
    if not shutil.which("lvs"):
        return []
    out = cmd_out(["lvs", "--noheadings", "--readonly", "-o", "vg_name,lv_name"])
    lvs = []
    for line in out.splitlines():
        cols = line.strip().split()
        if len(cols) == 2:
            dev = f"/dev/{cols[0]}/{cols[1]}"
            if Path(dev).exists():
                lvs.append(dev)
    return lvs

def lvm_mapper_path(dev_path: str) -> str:
    """
    Convert /dev/<vg>/<lv> to /dev/mapper/<vg>-<lv>.
    LVM uses double-dashes to escape real dashes in names:
      /dev/ubuntu-vg/ubuntu-lv  →  /dev/mapper/ubuntu--vg-ubuntu--lv
    This is the path mount actually uses; /dev/<vg>/<lv> is a symlink to it
    but mount and blkid are more reliable with the /dev/mapper/ path directly.
    """
    rel   = Path(dev_path).relative_to("/dev")   # e.g. ubuntu-vg/ubuntu-lv
    parts = rel.parts                             # ('ubuntu-vg', 'ubuntu-lv')
    # Escape dashes in each component by doubling them
    escaped = [p.replace("-", "--") for p in parts]
    mapper_name = "-".join(escaped)               # ubuntu--vg-ubuntu--lv
    return f"/dev/mapper/{mapper_name}"


def lvm_mount_lvs(mp_base: Path, part_label: str, readonly: bool,
                  state: MountState, dry_run: bool) -> int:
    """
    Mount LVs that are newly active after vgchange -ay.
    Uses /dev/mapper/<vg>-<lv> paths (not /dev/<vg>/<lv> symlinks) because
    mount -t ext4 -o ro,noload is more reliable with the mapper path directly.
    """
    if dry_run:
        lv_devs = ["/dev/ubuntu-vg/ubuntu-lv"]
    else:
        lv_devs = lvm_active_lvs()
        if not lv_devs:
            log.warning("  No active LVs found after vgchange -ay")
            return 0

        # Only process LVs not already mounted from a previous VMDK in this run
        new_lvs = []
        for dev in lv_devs:
            already = cmd_out(["findmnt", "-n", "-o", "TARGET", "--source", dev])
            if not already:
                # Also check the mapper path
                mapper = lvm_mapper_path(dev)
                already = cmd_out(["findmnt", "-n", "-o", "TARGET", "--source", mapper])
            if already:
                log.debug(f"    Skipping {dev} — already mounted at {already}")
            else:
                new_lvs.append(dev)

        lv_devs = new_lvs
        if not lv_devs:
            log.warning("  All active LVs already mounted — none new from this PV")
            return 0

    log.info(f"  Mounting {len(lv_devs)} new logical volume(s)")
    lvm_base = mp_base / f"{part_label}_lvm"
    lvm_base.mkdir(parents=True, exist_ok=True)
    mounted = 0

    for lv_dev in lv_devs:
        # Use /dev/mapper/ path — more reliable for mount than the /dev/vg/lv symlink
        mapper_dev = lvm_mapper_path(lv_dev) if not dry_run else lv_dev
        use_dev    = mapper_dev if Path(mapper_dev).exists() else lv_dev

        # Detect filesystem — try both paths, mapper first
        fs = ""
        if not dry_run:
            fs = detect_fs(use_dev)
            if not fs and use_dev != lv_dev:
                fs = detect_fs(lv_dev)
            log.info(f"    LV device : {use_dev}")
            log.info(f"    Filesystem: {fs or '(blkid returned nothing — will try ext4)'}")

        if fs in UNMOUNTABLE_FS:
            log.warning(f"    Skipping {use_dev} — '{fs}' not mountable")
            continue

        # Build mount point from the /dev/<vg>/<lv> name
        rel   = Path(lv_dev).relative_to("/dev")
        lv_mp = lvm_base / rel
        lv_mp.mkdir(parents=True, exist_ok=True)

        log.info(f"    Mounting {use_dev} → {lv_mp}")

        # If blkid returned nothing, force-try ext4 with noload first
        # (common for LVM LVs on VMDKs — blkid sometimes can't read through
        # the device mapper layer but mount handles it fine)
        if not fs:
            log.info(f"    blkid returned no fs type — trying ext4 ro,noload directly")
            try:
                run(["mount", "-t", "ext4", "-o", "ro,noload", use_dev, str(lv_mp)],
                    dry_run=dry_run, check=True, capture=True)
                log.info(f"    ✓ Mounted (forced ext4 noload) {use_dev} → {lv_mp}")
                state.partitions.append(str(lv_mp))
                state.lvm_volume_groups.append(lv_dev)
                mounted += 1
                continue
            except RuntimeError as e:
                log.warning(f"    forced ext4 failed: {e}")
                # Fall through to do_mount generic attempts
                fs = ""

        if do_mount(use_dev, lv_mp, fs, readonly, dry_run):
            state.partitions.append(str(lv_mp))
            state.lvm_volume_groups.append(lv_dev)
            mounted += 1
        else:
            # Last resort — try the exact command that works manually
            log.info(f"    Trying exact manual command: mount -t ext4 -o ro,noload {use_dev}")
            try:
                run(["mount", "-t", "ext4", "-o", "ro,noload", use_dev, str(lv_mp)],
                    dry_run=dry_run, check=True, capture=True)
                log.info(f"    ✓ Mounted (manual fallback) {use_dev} → {lv_mp}")
                state.partitions.append(str(lv_mp))
                state.lvm_volume_groups.append(lv_dev)
                mounted += 1
            except RuntimeError as e:
                log.error(f"    ✗ All attempts failed for {use_dev}: {e}")
                try: lv_mp.rmdir()
                except Exception: pass

    if mounted == 0:
        try: lvm_base.rmdir()
        except Exception: pass
    return mounted


# ── dmsetup cleanup ───────────────────────────────────────────────────────────
def dmsetup_remove_lvm(dry_run: bool):
    """
    Remove device mapper entries that belong to LVM (not kpartx).
    kpartx entries look like loopXpY or nbdXpY — leave those alone.
    Everything else (LVM LVs) gets removed so block devices can detach.
    """
    if not shutil.which("dmsetup"):
        return
    out = cmd_out(["dmsetup", "ls"])
    if not out:
        return
    kpartx_pat = re.compile(r"^(loop|nbd)\d+p\d+$")
    entries = [
        cols[0] for line in out.splitlines()
        if (cols := line.split()) and cols[0] != "control"
        and not kpartx_pat.match(cols[0])
    ]
    if not entries:
        log.debug("  No LVM dm entries to remove")
        return
    log.info(f"  Removing {len(entries)} LVM dm entries")
    for name in entries:
        log.info(f"    dmsetup remove --force {name}")
        try:
            run(["dmsetup", "remove", "--force", name],
                dry_run=dry_run, check=False, capture=True)
            time.sleep(0.1)
        except Exception as e:
            log.warning(f"    {e}")


# ── kpartx ────────────────────────────────────────────────────────────────────
def kpartx_add(dev: str, dry_run: bool) -> list[str]:
    """Map partitions via kpartx. Returns /dev/mapper/... device list."""
    run(["kpartx", "-asv", dev], dry_run=dry_run, check=False, capture=True)
    time.sleep(0.5)
    if dry_run:
        return [f"/dev/mapper/{Path(dev).name}p1_DRYRUN"]
    dev_name = Path(dev).name
    parts = sorted(glob.glob(f"/dev/mapper/{dev_name}p*"))
    log.debug(f"  kpartx mapped: {parts}")
    return parts

def kpartx_remove(dev: str):
    try:
        run(["kpartx", "-d", dev], check=False, capture=True)
        log.info(f"  kpartx -d {dev}")
    except Exception as e:
        log.warning(f"  kpartx remove failed for {dev}: {e}")


# ── losetup ───────────────────────────────────────────────────────────────────
def losetup_attach(image_path: str, readonly: bool) -> str:
    """
    Attach image as a loop device WITHOUT --partscan.
    --partscan would make the kernel create /dev/loopXpY partition nodes at
    the same time kpartx creates /dev/mapper/loopXpY — LVM sees both sets
    as duplicate PVs and refuses to activate. kpartx is our sole partition
    mapper; losetup just exposes the raw image as a block device.
    """
    cmd = ["losetup", "--find", "--show"]
    if readonly:
        cmd.append("--read-only")
    cmd.append(image_path)
    r = run(cmd, capture=True)
    dev = r.stdout.strip()
    if not dev:
        raise RuntimeError(f"losetup returned no device for {image_path}")
    log.debug(f"  Loop device: {dev}")
    return dev

def losetup_detach(dev: str):
    try:
        run(["losetup", "-d", dev], check=True, capture=True)
        log.info(f"  losetup -d {dev}")
    except Exception as e:
        log.warning(f"  losetup detach failed for {dev}: {e}")


# ── NBD ───────────────────────────────────────────────────────────────────────
NBD_TIMEOUT = 15
NBD_POLL    = 0.5

def nbd_get_max() -> int:
    try:
        return int(Path("/sys/module/nbd/parameters/nbds_max").read_text().strip())
    except Exception:
        return 16

def nbd_is_free(index: int) -> bool:
    name = f"nbd{index}"
    if Path(f"/sys/block/{name}/pid").exists():
        return False
    try:
        if int(Path(f"/sys/block/{name}/size").read_text().strip()) != 0:
            return False
    except Exception:
        pass
    # Also check no qemu-nbd process is referencing this device
    try:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="ignore")
                if f"/dev/{name}" in cmdline and "qemu-nbd" in cmdline:
                    return False
            except Exception:
                continue
    except Exception:
        pass
    return True

def nbd_find_free() -> Optional[str]:
    max_slots = nbd_get_max()
    for i in range(max_slots):
        dev = f"/dev/nbd{i}"
        if Path(dev).exists() and nbd_is_free(i):
            remaining = sum(1 for j in range(i+1, max_slots)
                           if Path(f"/dev/nbd{j}").exists() and nbd_is_free(j))
            if remaining <= 2:
                log.warning(f"  Only {remaining+1} NBD slot(s) remaining — "
                            f"consider --unmount or run: rmmod nbd && modprobe nbd nbds_max=32")
            return dev
    log.error(f"  All {max_slots} NBD slots in use. "
              f"Run --unmount or: rmmod nbd && modprobe nbd nbds_max=32")
    return None

def nbd_connect(img: Path, readonly: bool, state: MountState, dry_run: bool) -> Optional[str]:
    """
    Connect image to a free NBD device via qemu-nbd.
    qemu-nbd handles all VMDK subtypes (sparse, split, VMFS, snapshots).

    NOTE: We do NOT call modprobe here. The nbd module must already be loaded
    (it is, as long as /dev/nbd* devices exist). Reloading it with different
    parameters while devices are in use causes exactly the duplicate-device
    problem we had before. If you need more slots: rmmod nbd && modprobe nbd
    nbds_max=32 BEFORE running this script.
    """
    if not Path("/dev/nbd0").exists():
        log.error("  NBD devices not found. Load module first: modprobe nbd nbds_max=16 max_part=0")
        return None

    dev = nbd_find_free() if not dry_run else "/dev/nbd_DRYRUN"
    if not dev:
        return None

    ro_flag = ["--read-only"] if readonly else []
    try:
        run(["qemu-nbd", "--connect", dev] + ro_flag + [str(img)],
            dry_run=dry_run, check=True, capture=True, timeout=30)
    except RuntimeError as e:
        log.error(f"  qemu-nbd connect failed: {e}")
        return None

    if not dry_run:
        # Wait for kernel to finish setting up the device
        idx = int(re.search(r"\d+$", dev).group())
        size_p = Path(f"/sys/block/nbd{idx}/size")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if int(size_p.read_text().strip()) > 0:
                    break
            except Exception:
                pass
            time.sleep(0.25)
        else:
            log.error(f"  qemu-nbd connected to {dev} but size stayed 0 — corrupt image?")
            try:
                run(["qemu-nbd", "--disconnect", dev], check=False, capture=True, timeout=10)
            except Exception:
                pass
            return None

    state.nbd_devices.append(dev)
    log.debug(f"  NBD connected: {dev}")
    return dev

def nbd_disconnect(dev: str, dry_run: bool):
    """
    Disconnect a qemu-nbd device.
    We do NOT poll waiting for the slot to be "confirmed free" — that loop was
    the cause of the long hangs. By the time we call this, all filesystems on
    the device have already been unmounted and LVM deactivated, so the device
    is no longer held open. qemu-nbd --disconnect is sufficient; the kernel
    releases the slot asynchronously but we don't need to wait for it.
    """
    if dry_run:
        log.info(f"  [DRY-RUN] qemu-nbd --disconnect {dev}")
        return
    log.info(f"  Disconnecting NBD: {dev}")
    try:
        run(["qemu-nbd", "--disconnect", dev], check=False, capture=True, timeout=10)
        log.info(f"  NBD {dev} disconnected")
    except Exception as e:
        log.warning(f"  qemu-nbd --disconnect {dev}: {e}")


# ── Partition discovery ───────────────────────────────────────────────────────
def get_partitions_for(dev: str, use_kpartx: bool, dry_run: bool) -> list[str]:
    """
    Return the list of partition device paths for a block device.

    For loop devices  → use kpartx (/dev/mapper/loopXpY)
    For NBD devices   → read /dev/nbdXpY directly (qemu-nbd already created them)

    This is the key fix for the duplicate device problem:
    qemu-nbd with a connected VMDK automatically exposes partition devices at
    /dev/nbd0p1, /dev/nbd0p2 etc. If we ALSO run kpartx on it, we get a
    second set in /dev/mapper/ — LVM then sees the same PV UUID twice and
    reports "duplicate PV" refusing to activate. So for NBD we skip kpartx
    entirely and use the devices qemu-nbd already made.
    """
    if dry_run:
        return [f"{dev}p1_DRYRUN", f"{dev}p2_DRYRUN"]

    if use_kpartx:
        return kpartx_add(dev, dry_run=False)
    else:
        # NBD: wait briefly for kernel to expose partition nodes, then read them
        time.sleep(1)
        dev_name = Path(dev).name  # nbd0
        parts = sorted(glob.glob(f"/dev/{dev_name}p*"))
        log.debug(f"  NBD partitions found: {parts}")
        return parts


# ── Mount all partitions on a block device ────────────────────────────────────
def mount_partitions(blk_dev: str, mp_base: Path, readonly: bool,
                     state: MountState, dry_run: bool,
                     use_kpartx: bool = True) -> int:
    """
    Enumerate and mount all partitions on blk_dev.
    use_kpartx=True  for loop devices (E01, raw, AFF)
    use_kpartx=False for NBD devices  (VMDK, QCOW2) — uses /dev/nbdXpY directly
    """
    log.info(f"  Discovering partitions on {blk_dev}")
    parts = get_partitions_for(blk_dev, use_kpartx, dry_run)

    if not parts:
        # No partition table — the whole device might be a raw filesystem
        # OR an LVM PV with no partition table (common in VMDKs)
        fs = detect_fs(blk_dev) if not dry_run else "ext4"
        log.info(f"  No partitions found on {blk_dev} — detected: {fs or 'unknown'}")

        if fs == "lvm2_member":
            # Whole device is an LVM PV — activate and mount LVs
            log.info(f"  Whole device is LVM PV — running vgchange -ay")
            if lvm_activate(dry_run):
                time.sleep(1)
                n = lvm_mount_lvs(mp_base, "volume", readonly, state, dry_run)
                if n > 0:
                    return n
            log.error(f"  LVM activation/mount failed for {blk_dev}")
            return 0

        if fs in UNMOUNTABLE_FS:
            log.warning(f"  Skipping {blk_dev} — '{fs}' not mountable")
            return 0

        # Try as a plain filesystem
        log.info(f"  Attempting direct mount of {blk_dev}")
        mp = mp_base / "volume"
        mp.mkdir(parents=True, exist_ok=True)
        if do_mount(blk_dev, mp, fs, readonly, dry_run):
            state.partitions.append(str(mp))
            return 1
        try: mp.rmdir()
        except Exception: pass
        log.error(f"  Could not mount {blk_dev}")
        return 0

    mounted = 0
    for i, part in enumerate(parts, start=1):
        part_label = f"part{i}"
        if not dry_run:
            desc = describe_part(part)
            log.info(f"  Partition {i}: {part}  [{desc}]")
            info = blkid_info(part)
            fs   = info.get("TYPE", "").lower()
            if info.get("LABEL"): log.info(f"    Label: {info['LABEL']}")
            if info.get("UUID"):  log.info(f"    UUID:  {info['UUID']}")

            # LVM Physical Volume
            if fs == "lvm2_member":
                log.info(f"    LVM PV detected — running vgchange -ay")
                if lvm_activate(dry_run):
                    time.sleep(1)
                    n = lvm_mount_lvs(mp_base, part_label, readonly, state, dry_run)
                    mounted += n
                else:
                    log.error(f"    vgchange -ay failed for {part}")
                continue

            if fs in UNMOUNTABLE_FS:
                log.warning(f"    Skipping {part} — '{fs}' not mountable"
                            + (" (needs decryption key)" if "luks" in fs else ""))
                continue
        else:
            fs = "ext4"

        mp = mp_base / part_label
        mp.mkdir(parents=True, exist_ok=True)
        if do_mount(part, mp, fs, readonly, dry_run):
            state.partitions.append(str(mp))
            mounted += 1
        else:
            try: mp.rmdir()
            except Exception: pass

    return mounted


# ── Format mounters ───────────────────────────────────────────────────────────

def mount_raw(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    log.info(f"Mounting RAW: {img}")
    try:
        dev = losetup_attach(str(img), readonly) if not dry_run else "/dev/loop_DRY"
        state.loop_devices.append(dev)
        return mount_partitions(dev, mp_base, readonly, state, dry_run,
                                use_kpartx=True) > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  {e}")
        return False


def mount_ewf(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    if not shutil.which("ewfmount"):
        log.error("ewfmount not found — apt install ewf-tools")
        return False
    log.info(f"Mounting EWF: {img}")

    fuse_mp = mp_base / ".ewf_fuse"
    fuse_mp.mkdir(parents=True, exist_ok=True)
    try:
        run(["ewfmount", str(img), str(fuse_mp)], dry_run=dry_run,
            check=True, capture=True)
        state.fuse_mounts.append(str(fuse_mp))
    except RuntimeError as e:
        log.error(f"  ewfmount failed: {e}")
        try: fuse_mp.rmdir()
        except Exception: pass
        return False

    # Find the raw file ewfmount exposed
    raw_file = fuse_mp / "ewf1"
    if not dry_run and not raw_file.exists():
        candidates = list(fuse_mp.iterdir())
        if candidates:
            raw_file = candidates[0]
        else:
            log.error(f"  No raw file in {fuse_mp}")
            return False

    try:
        dev = losetup_attach(str(raw_file), readonly) if not dry_run else "/dev/loop_DRY"
        state.loop_devices.append(dev)
        return mount_partitions(dev, mp_base, readonly, state, dry_run,
                                use_kpartx=True) > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  EWF loop attach failed: {e}")
        return False


def mount_vmdk(img: Path, mp_base: Path, readonly: bool,
               state: MountState, dry_run: bool) -> bool:
    if not shutil.which("qemu-nbd"):
        log.error("qemu-nbd not found — apt install qemu-utils")
        return False
    log.info(f"Mounting VMDK: {img}")
    dev = nbd_connect(img, readonly, state, dry_run)
    if not dev:
        return False
    # use_kpartx=False — qemu-nbd already created /dev/nbd0p1 etc
    return mount_partitions(dev, mp_base, readonly, state, dry_run,
                            use_kpartx=False) > 0 or dry_run


def mount_qcow2(img: Path, mp_base: Path, readonly: bool,
                state: MountState, dry_run: bool) -> bool:
    if not shutil.which("qemu-nbd"):
        log.error("qemu-nbd not found — apt install qemu-utils")
        return False
    log.info(f"Mounting QCOW2: {img}")
    dev = nbd_connect(img, readonly, state, dry_run)
    if not dev:
        return False
    return mount_partitions(dev, mp_base, readonly, state, dry_run,
                            use_kpartx=False) > 0 or dry_run


def mount_aff(img: Path, mp_base: Path, readonly: bool,
              state: MountState, dry_run: bool) -> bool:
    if not shutil.which("affuse"):
        log.error("affuse not found — apt install afflib-tools")
        return False
    log.info(f"Mounting AFF: {img}")

    fuse_mp = mp_base / ".aff_fuse"
    fuse_mp.mkdir(parents=True, exist_ok=True)
    try:
        run(["affuse", str(img), str(fuse_mp)], dry_run=dry_run,
            check=True, capture=True)
        state.fuse_mounts.append(str(fuse_mp))
    except RuntimeError as e:
        log.error(f"  affuse failed: {e}")
        try: fuse_mp.rmdir()
        except Exception: pass
        return False

    raw_file = fuse_mp / f"{img.name}.raw"
    if not dry_run and not raw_file.exists():
        candidates = [f for f in fuse_mp.iterdir() if f.suffix == ".raw"]
        if candidates:
            raw_file = candidates[0]
        else:
            log.error(f"  No .raw file in {fuse_mp}")
            return False

    try:
        dev = losetup_attach(str(raw_file), readonly) if not dry_run else "/dev/loop_DRY"
        state.loop_devices.append(dev)
        return mount_partitions(dev, mp_base, readonly, state, dry_run,
                                use_kpartx=True) > 0 or dry_run
    except RuntimeError as e:
        log.error(f"  AFF loop attach failed: {e}")
        return False


# ── Dispatcher ────────────────────────────────────────────────────────────────
MOUNTERS = {
    **{e: mount_ewf   for e in EWF_FIRST_EXTS},
    **{e: mount_raw   for e in RAW_EXTS},
    **{e: mount_vmdk  for e in VMDK_EXTS},
    **{e: mount_qcow2 for e in QCOW_EXTS},
    **{e: mount_aff   for e in AFF_EXTS},
}

def sanitise(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name.replace(" ", "_"))

def is_ewf_segment(ext: str) -> bool:
    return EWF_SEG_PAT.match(ext.lower()) is not None and ext.lower() not in EWF_FIRST_EXTS

def process_image(img: Path, hostname: str, label: str,
                  mount_base: Path, readonly: bool, dry_run: bool) -> bool:
    ext     = img.suffix.lower()
    mounter = MOUNTERS.get(ext, mount_raw)
    if ext not in MOUNTERS:
        log.warning(f"Unknown extension '{ext}' — trying raw mount")

    mp_base = mount_base / hostname / label
    mp_base.mkdir(parents=True, exist_ok=True)

    state = MountState(image_path=str(img), mount_base=str(mp_base))
    ok = mounter(img, mp_base, readonly, state, dry_run)
    state.save()

    if not ok:
        log.error(f"Failed to mount: {img}")
        try:
            if mp_base.exists() and not any(mp_base.iterdir()):
                mp_base.rmdir()
        except Exception:
            pass
    return ok


# ── Discovery ─────────────────────────────────────────────────────────────────
def discover(evidence_root: Path) -> list[tuple[Path, str, str]]:
    results: list[tuple[Path, str, str]] = []
    seen: dict[str, set[str]] = {}

    for f in sorted(evidence_root.rglob("*")):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext not in ALL_EXTS and not EWF_SEG_PAT.match(ext):
            continue
        if is_ewf_segment(ext):
            log.debug(f"Skipping EWF segment: {f}")
            continue

        rel   = f.relative_to(evidence_root)
        parts = rel.parts
        hostname = sanitise(evidence_root.name if len(parts) == 1 else parts[0])

        base  = sanitise(f.stem)
        label = f"{base}{f.suffix}"
        used  = seen.setdefault(hostname, set())
        n = 1
        while label in used:
            label = f"{base}_{n}{f.suffix}"
            n += 1
        used.add(label)
        results.append((f, hostname, label))

    return results


# ── Unmount ───────────────────────────────────────────────────────────────────
def _umount(mp: str, dry_run: bool):
    if not dry_run and not Path(mp).exists():
        return
    try:
        run(["umount", "-l", mp], dry_run=dry_run, check=True, capture=True)
        log.info(f"  Unmounted: {mp}")
    except RuntimeError as e:
        log.warning(f"  umount {mp}: {e}")

def unmount_all(mount_base: Path, dry_run: bool):
    banner("Unmounting all evidence", str(mount_base))
    if not mount_base.exists():
        log.warning(f"{mount_base} does not exist")
        return

    state_files = sorted(mount_base.rglob(STATE_FILE), reverse=True)

    if not state_files:
        # Fallback — no state files, do best-effort from /proc/mounts
        log.warning("No state files found — falling back to /proc/mounts")
        mounts = []
        try:
            for line in Path("/proc/mounts").read_text().splitlines():
                cols = line.split()
                if len(cols) >= 2 and cols[1].startswith(str(mount_base)):
                    mounts.append(cols[1])
        except Exception:
            pass
        for mp in sorted(mounts, reverse=True):
            _umount(mp, dry_run)
        lvm_deactivate(dry_run)
        dmsetup_remove_lvm(dry_run)
        return

    for sf in state_files:
        state = MountState.load(str(sf.parent))
        if not state:
            continue
        log.info(f"\n── Teardown: {state.image_path}")

        # 1. Unmount filesystems (deepest path first)
        for mp in sorted(state.partitions, reverse=True):
            _umount(mp, dry_run)

        # 2. Deactivate LVM and clean dm entries (only if LVM was used)
        if state.lvm_volume_groups:
            lvm_deactivate(dry_run)
            dmsetup_remove_lvm(dry_run)

        # 3. Release loop devices (kpartx then losetup)
        for dev in state.loop_devices:
            if not dry_run:
                kpartx_remove(dev)
                losetup_detach(dev)
            else:
                log.info(f"  [DRY-RUN] kpartx -d {dev} && losetup -d {dev}")

        # 4. Disconnect NBD devices
        for dev in state.nbd_devices:
            nbd_disconnect(dev, dry_run)

        # 5. Unmount FUSE mounts (ewfmount/affuse) — must be last
        for mp in state.fuse_mounts:
            _umount(mp, dry_run)

        if not dry_run:
            try: sf.unlink()
            except Exception: pass

    log.info("Cleaning empty directories...")
    if not dry_run:
        for dirpath, _, _ in os.walk(str(mount_base), topdown=False):
            p = Path(dirpath)
            if p == mount_base: continue
            try:
                if not any(p.iterdir()):
                    p.rmdir()
            except Exception:
                pass

    banner("Unmount complete")


# ── UI ────────────────────────────────────────────────────────────────────────
def banner(title: str, detail: str = ""):
    line = "═" * 54
    print(f"\n{BOLD}{CYAN}{line}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    if detail: print(f"{CYAN}  {detail}{RESET}")
    print(f"{BOLD}{CYAN}{line}{RESET}")

def print_summary(results: list[tuple[str,bool]], mount_base: Path, log_file: str, dry_run: bool):
    ok     = sum(1 for _,s in results if s)
    failed = sum(1 for _,s in results if not s)
    print(f"\n{BOLD}{'═'*46}{RESET}")
    print(f"{BOLD}  Mount Summary{RESET}")
    print(f"{'─'*46}")
    print(f"  Total   : {len(results)}")
    print(f"  {GREEN}OK      : {ok}{RESET}")
    print(f"  {'  ' if not failed else RED}Failed  : {failed}{RESET if failed else ''}")
    print(f"{'─'*46}")
    print(f"  Mount base : {mount_base}")
    print(f"  Log        : {log_file}")
    print(f"{BOLD}{'═'*46}{RESET}\n")
    if ok > 0 and not dry_run and mount_base.exists():
        print(f"{CYAN}Mount tree:{RESET}")
        _tree(mount_base)

def _tree(path: Path, prefix="  ", depth=0, max_depth=4):
    if depth >= max_depth: return
    try:
        entries = sorted(e for e in path.iterdir() if not e.name.startswith("."))
    except PermissionError:
        return
    for i, e in enumerate(entries):
        last = i == len(entries) - 1
        print(f"{prefix}{'└── ' if last else '├── '}{e.name}")
        if e.is_dir():
            _tree(e, prefix + ("    " if last else "│   "), depth+1, max_depth)


# ── CLI ───────────────────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="mount_evidence.py",
        description="Forensic Evidence Mass Mounter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("evidence_root", nargs="?", metavar="EVIDENCE_ROOT")
    p.add_argument("-o", "--mount-base", default="/mnt/IOC_SCAN")
    p.add_argument("-l", "--log",        default="/var/log/mount_evidence.log")
    p.add_argument("-r", "--readonly",   dest="readonly", action="store_true",  default=True)
    p.add_argument("-w", "--readwrite",  dest="readonly", action="store_false")
    p.add_argument("-d", "--dry-run",    action="store_true")
    p.add_argument("-u", "--unmount",    action="store_true")
    p.add_argument("-v", "--verbose",    action="store_true")
    p.add_argument("--nbd-max", type=int, default=0, metavar="N",
                   help="Increase NBD slots: rmmod nbd && modprobe nbd nbds_max=N max_part=0")
    return p


def main() -> int:
    global log
    args   = build_parser().parse_args()
    log    = setup_logging(args.log, args.verbose)

    if os.geteuid() != 0:
        log.error("Must run as root")
        return 1

    mount_base = Path(args.mount_base)

    if args.unmount:
        unmount_all(mount_base, args.dry_run)
        return 0

    if not args.evidence_root:
        build_parser().print_help()
        return 1

    evidence_root = Path(args.evidence_root).resolve()
    if not evidence_root.is_dir():
        log.error(f"Not a directory: {evidence_root}")
        return 1

    # Optionally increase NBD slots — must be done before any NBD connection
    if args.nbd_max > 0:
        current = nbd_get_max()
        if args.nbd_max != current:
            log.info(f"Reloading nbd module: nbds_max={args.nbd_max} max_part=0")
            try:
                run(["rmmod", "nbd"], check=True, capture=True)
                run(["modprobe", "nbd", f"nbds_max={args.nbd_max}", "max_part=0"],
                    check=True, capture=True)
                log.info(f"NBD slots: {nbd_get_max()}")
            except RuntimeError as e:
                log.warning(f"Could not reload nbd: {e}")

    check_deps()
    mount_base.mkdir(parents=True, exist_ok=True)

    images = discover(evidence_root)
    if not images:
        log.error(f"No forensic images found under {evidence_root}")
        log.error(f"Supported: {', '.join(sorted(ALL_EXTS))}")
        return 1

    banner("Forensic Evidence Mass Mounter",
           f"Root: {evidence_root} | Base: {mount_base} | "
           f"Mode: {'READ-ONLY' if args.readonly else 'READ-WRITE ⚠'} | "
           f"Images: {len(images)}")

    results: list[tuple[str, bool]] = []
    for img, hostname, label in images:
        print(f"\n{BOLD}── {hostname} / {label}{RESET}")
        ok = process_image(img, hostname, label, mount_base, args.readonly, args.dry_run)
        results.append((str(img), ok))

    print_summary(results, mount_base, args.log, args.dry_run)
    return 1 if any(not ok for _, ok in results) else 0


if __name__ == "__main__":
    sys.exit(main())
