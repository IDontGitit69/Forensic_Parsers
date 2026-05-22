# ForensicMounter

> **A forensic-grade disk image mass mounter for Linux — built for incident response and IOC scanning.**

ForensicMounter recursively discovers and mounts forensic disk images from an evidence directory tree, handling partition mapping, LVM activation, and VMFS volumes automatically. Designed for use with THOR, YARA, Autopsy, or any other forensic scanning tool.

---

## ⚠️ Important Notices

> **This tool is designed for use on a dedicated Linux VM or bare-metal forensic workstation. It is NOT compatible with WSL (Windows Subsystem for Linux).** WSL2 does not support the kernel modules required for disk image mounting (nbd, device mapper, loop devices with kpartx). If you are working on Windows, use Arsenal Image Mounter (AIM) instead.

> **Always run as root.** Disk mounting operations require root privileges.

> **This tool mounts images read-only by default.** Write access (`--readwrite`) is available but forensically unsafe and should never be used on original evidence.

---

## Table of Contents

- [Project Name & Background](#project-name--background)
- [Supported Formats](#supported-formats)
- [Supported Partition & Filesystem Types](#supported-partition--filesystem-types)
- [Requirements](#requirements)
- [Installation](#installation)
- [Directory Structure](#directory-structure)
- [Usage](#usage)
- [Mount Layout](#mount-layout)
- [How It Works](#how-it-works)
- [Using with THOR](#using-with-thor)
- [Unmounting](#unmounting)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)

---

## Project Name & Background

**ForensicMounter** was built out of a real need during incident response investigations involving VMware vCenter environments — where a single host can produce 10+ VMDK files, each potentially containing multiple partitions, LVM volumes, and VMFS datastores. Existing tools either mounted one image at a time or lacked LVM/VMFS awareness. ForensicMounter handles the full stack automatically and tears everything down cleanly when you're done.

---

## Supported Formats

| Format | Extension(s) | Method |
|--------|-------------|--------|
| Expert Witness Format | `.E01` `.Ex01` `.L01` `.S01` | ewfmount → losetup → kpartx |
| Raw disk image | `.raw` `.img` `.dd` `.bin` | losetup → kpartx |
| VMware disk | `.vmdk` | qemu-nbd |
| QEMU image | `.qcow2` `.qcow` | qemu-nbd |
| AFF image | `.aff` `.afd` `.afm` | affuse → losetup → kpartx |

**VMDK notes:**
- Sparse, monolithic-flat (descriptor + flat file pairs), and split VMDKs are all supported
- Flat data files (e.g. `disk-flat.vmdk`) are automatically detected by file signature and skipped — only the descriptor is mounted, preventing duplicate mounts
- VMFS volumes within VMDKs are mounted via `vmfs6-fuse`

---

## Supported Partition & Filesystem Types

| Type | Handling |
|------|----------|
| ext2 / ext3 / ext4 | Mounted read-only with `noload` (no journal replay) |
| NTFS | Mounted via ntfs-3g with forensic flags |
| vfat / FAT32 / exFAT | Mounted read-only |
| XFS | Mounted with `norecovery` |
| btrfs / HFS+ / UDF / ISO9660 / squashfs | Mounted read-only |
| **LVM2 Physical Volume** | `vgchange -ay` → all LVs mounted automatically |
| **VMFS volume member** | Mounted via vmfs6-fuse |
| swap | Skipped with log message |
| LUKS encrypted | Skipped with log message (key required) |
| Linux RAID member | Skipped with log message |

---

## Requirements

### System

- Linux (Ubuntu 20.04+ recommended) on a **real VM or bare-metal** — not WSL
- Python 3.8+
- Root / sudo access

### Kernel modules

```bash
# Ensure NBD is loaded with correct parameters (persistent across reboots)
echo "options nbd nbds_max=32 max_part=0" | sudo tee /etc/modprobe.d/nbd.conf
sudo update-initramfs -u

# Apply immediately without rebooting
sudo modprobe nbd nbds_max=32 max_part=0
```

> **Why `max_part=0`?** With `max_part>0`, the kernel auto-creates `/dev/nbd0p1`, `/dev/nbd0p2` etc. at the same time kpartx creates `/dev/mapper/nbd0p1` etc. — LVM sees both sets as duplicate Physical Volumes and refuses to activate. Setting `max_part=0` lets kpartx be the sole partition mapper, eliminating the duplicate PV error.

### Python dependencies

ForensicMounter uses only Python standard library — no `pip install` required.

### System packages

```bash
sudo apt update && sudo apt install -y \
    ewf-tools \
    qemu-utils \
    kpartx \
    ntfs-3g \
    util-linux \
    afflib-tools \
    lvm2 \
    dmsetup \
    fuse
```

### VMFS support (optional)

VMFS volumes require `vmfs6-fuse`. Install it to `/usr/local/bin/`:

```bash
# Build from source (https://github.com/libyal/libvmdk) or use a pre-built binary
sudo cp /path/to/vmfs6-fuse /usr/local/bin/
sudo chmod +x /usr/local/bin/vmfs6-fuse

# Enable allow_other for GUI file manager access
echo "user_allow_other" | sudo tee -a /etc/fuse.conf
```

---

## Installation

```bash
git clone https://github.com/yourusername/forensicmounter.git
cd forensicmounter
chmod +x mount_evidence.py
```

No virtual environment or dependencies needed beyond the system packages above.

---

## Directory Structure

ForensicMounter expects your evidence to be organised with one subdirectory per host:

```
/evidence/
  Case001/
    DC01/                          ← hostname directory
      DC01_Disk0.E01
      DC01_Disk0.E02               ← EWF segments auto-discovered, not mounted separately
      DC01_Disk1.E01
    VCENTER01/                     ← hostname directory
      clone-vcenter-s001.vmdk      ← descriptor, mounts and finds flat automatically
      clone-vcenter-s001-flat.vmdk ← skipped (detected by file signature)
      clone-vcenter-s002.vmdk
      clone-vcenter-s002-flat.vmdk
    FILESERVER01/
      fileserver01.img
```

> If images are placed directly in the evidence root (no subdirectory), the evidence root directory name is used as the hostname.

---

## Usage

### Basic mount

```
sudo python3 mount_evidence.py <evidence_root>
```

```
sudo python3 mount_evidence.py /evidence/Case001/
```

**Example output:**
```
══════════════════════════════════════════════════════
  Forensic Evidence Mass Mounter
  Root: /evidence/Case001 | Base: /mnt/IOC_SCAN | Mode: READ-ONLY | Images: 5
══════════════════════════════════════════════════════

── DC01 / DC01_Disk0.E01
[INFO] Mounting EWF: /evidence/Case001/DC01/DC01_Disk0.E01
[INFO]   LVM: vgchange -ay
[INFO]   Partition 1: /dev/mapper/loop0p1  [vfat, label="EFI"]
[INFO]     ✓ Mounted [vfat-specific] /dev/mapper/loop0p1 → /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part1
[INFO]   Partition 2: /dev/mapper/loop0p2  [ext4]
[INFO]     ✓ Mounted [ext4-specific] /dev/mapper/loop0p2 → /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part2
[INFO]   Partition 3: /dev/mapper/loop0p3  [lvm2_member]
[INFO]     LVM PV detected — running vgchange -ay
[INFO]     1 new LV(s) to mount
[INFO]     /dev/mapper/ubuntu--vg-ubuntu--lv  [ext4]
[INFO]     ✓ /dev/mapper/ubuntu--vg-ubuntu--lv → /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part3_lvm/ubuntu-vg-ubuntu-lv

── VCENTER01 / clone-vcenter-s001.vmdk
[INFO] Mounting VMDK: /evidence/Case001/VCENTER01/clone-vcenter-s001.vmdk
[INFO]   NBD connected: /dev/nbd0
[INFO]   Whole device is LVM PV — running vgchange -ay
[INFO]   1 new LV(s) to mount
[INFO]   /dev/mapper/data--vg-data--lv  [ext4]
[INFO]     ✓ /dev/mapper/data--vg-data--lv → /mnt/IOC_SCAN/VCENTER01/clone-vcenter-s001.vmdk/volume_lvm/data-vg-data-lv

══════════════════════════════════════════════════════
  Mount Summary
──────────────────────────────────────────────────────
  Total   : 5
  OK      : 5
  Failed  : 0
──────────────────────────────────────────────────────
  Mount base : /mnt/IOC_SCAN
  Log        : /var/log/mount_evidence.log
══════════════════════════════════════════════════════

Mount tree:
  ├── DC01
  │   └── DC01_Disk0.E01
  │       ├── part1
  │       ├── part2
  │       └── part3_lvm
  │           └── ubuntu-vg-ubuntu-lv
  └── VCENTER01
      └── clone-vcenter-s001.vmdk
          └── volume_lvm
              └── data-vg-data-lv
```

---

### All options

```
sudo python3 mount_evidence.py [OPTIONS] <evidence_root>
sudo python3 mount_evidence.py --unmount [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `<evidence_root>` | required | Root directory containing host subdirectories |
| `-o`, `--mount-base DIR` | `/mnt/IOC_SCAN` | Base directory for all mount points |
| `-l`, `--log FILE` | `/var/log/mount_evidence.log` | Log file path |
| `-r`, `--readonly` | true | Mount read-only (default, forensically safe) |
| `-w`, `--readwrite` | false | Mount read-write (**forensically unsafe**) |
| `-d`, `--dry-run` | false | Print all actions without executing |
| `-u`, `--unmount` | false | Tear down all mounts under mount base |
| `-v`, `--verbose` | false | Show debug output including every command run |
| `--nbd-max N` | 0 (no change) | Reload nbd module with `nbds_max=N` |

### Examples

```bash
# Mount with custom base directory
sudo python3 mount_evidence.py -o /mnt/CASE001 /evidence/Case001/

# Preview what would be mounted without doing anything
sudo python3 mount_evidence.py --dry-run /evidence/Case001/

# Mount with verbose output (shows every command)
sudo python3 mount_evidence.py -v /evidence/Case001/

# Mount with more NBD slots for large vCenter cases (11+ VMDKs)
sudo python3 mount_evidence.py --nbd-max 32 /evidence/Case001/VCENTER01/

# Unmount everything
sudo python3 mount_evidence.py --unmount

# Unmount from a custom base
sudo python3 mount_evidence.py --unmount -o /mnt/CASE001
```

---

## Mount Layout

```
/mnt/IOC_SCAN/
  <Hostname>/
    <ImageFilename>/
      part1/                    ← partition 1 filesystem
      part2/                    ← partition 2 filesystem
      part3_lvm/                ← LVM container partition
        <vg_name>-<lv_name>/   ← logical volume mount
      part4/                    ← VMFS volume (via vmfs6-fuse)
```

**State files** — each image mount base contains a hidden `.mount_state.json` file that records every loop device, NBD device, FUSE mount, and LVM volume created. The `--unmount` command reads these files to tear down exactly what was mounted, without touching anything else on the system (including the host OS LVM volumes).

---

## How It Works

### Mounting

```
1. discover()     Walks evidence_root, finds all image files
                  Skips EWF segments (.E02+), VMDK flat data files (by signature)
                  Groups images by hostname (parent directory name)

2. process_image()  Dispatches each image to the correct mounter:
                    .E01  → ewfmount → losetup → kpartx → mount_partitions()
                    .vmdk → qemu-nbd → get_partitions_for() → mount_partitions()
                    .raw  → losetup → kpartx → mount_partitions()

3. mount_partitions()  For each partition:
                       ext4/ntfs/vfat/etc  → do_mount() with fallback chain
                       lvm2_member         → vgchange -ay → lvm_mount_lvs()
                       vmfs_volume_member  → vmfs6-fuse
                       swap/luks/raid      → skip with log message

4. State saved to .mount_state.json in each image mount directory
```

### Unmounting

```
1. Read .mount_state.json from mount_base/*/*/
   (fixed 2-level glob — never walks into mounted filesystem contents)

2. Per image:
   umount -l all partition/LV mountpoints  (lazy — handles corrupt images)
   kpartx -d loop devices
   losetup -d loop devices
   kpartx -d NBD devices  (BEFORE disconnect — clears /dev/mapper/nbd0pX)
   qemu-nbd --disconnect NBD devices
   umount -l FUSE mounts (ewfmount, vmfs6-fuse)

3. Final pass (once, after all images):
   vgchange -an <evidence VGs only>  (never touches host OS LVM)
   dmsetup remove --force <evidence entries only>  (3 retries for busy devices)
```

---

## Using with THOR

### Basic lab scan

```bash
sudo ./thor64-linux --lab -p /mnt/IOC_SCAN/
```

### Recommended flags for mounted images

```bash
sudo ./thor64-linux --lab \
  --threads 4 \
  --intense \
  --norescontrol \
  -p /mnt/IOC_SCAN/
```

### Scan specific hosts

```bash
sudo ./thor64-linux --lab \
  --threads 8 \
  -p /mnt/IOC_SCAN/DC01/ \
  -p /mnt/IOC_SCAN/VCENTER01/ \
  -p /mnt/IOC_SCAN/FILESERVER01/
```

### Scan raw block devices (hits unallocated/slack space)

```bash
# Find the loop/NBD device for a specific image
losetup -l
lsblk

# Scan raw partition (includes deleted files, slack space)
sudo ./thor64-linux --lab --device /dev/mapper/loop0p2

# Scan entire raw image (includes inter-partition gaps)
sudo ./thor64-linux --lab --device /dev/loop0
```

> **Note:** Raw device scanning returns byte offsets rather than file paths. Use Sleuth Kit (`ifind`, `icat`) to correlate offsets back to files.

### Performance tips

- Store images on **local NVMe** — network shares (NFS/SMB/hgfs) add significant I/O overhead
- Use `--threads` to scan multiple images in parallel
- On kernel 5.15+, NTFS volumes can use the faster in-kernel `ntfs3` driver instead of ntfs-3g
- Ensure 16GB+ free RAM for large vCenter cases to benefit from kernel page cache

---

## Unmounting

```bash
sudo python3 mount_evidence.py --unmount
```

**Example output:**
```
══════════════════════════════════════════════════════
  Unmounting all evidence
  /mnt/IOC_SCAN
══════════════════════════════════════════════════════

── Teardown: /evidence/Case001/DC01/DC01_Disk0.E01
[INFO]   Unmounted: /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part3_lvm/ubuntu-vg-ubuntu-lv
[INFO]   Unmounted: /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part2
[INFO]   Unmounted: /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/part1
[INFO]   kpartx -d /dev/loop0
[INFO]   losetup -d /dev/loop0
[INFO]   Unmounted: /mnt/IOC_SCAN/DC01/DC01_Disk0.E01/.ewf_fuse

── Teardown: /evidence/Case001/VCENTER01/clone-vcenter-s001.vmdk
[INFO]   Unmounted: /mnt/IOC_SCAN/VCENTER01/clone-vcenter-s001.vmdk/volume_lvm/data-vg-data-lv
[INFO]   kpartx -d /dev/nbd0
[INFO]   NBD /dev/nbd0 disconnected

── Final cleanup
[INFO]   /dev/mapper entries remaining: ['data--vg-data--lv', 'nbd0p1']
[INFO]   vgchange -an data-vg
[INFO]   dmsetup pass 1/3: removing ['data--vg-data--lv', 'nbd0p1']
[INFO]   Removed: data--vg-data--lv
[WARN]   Could not remove nbd0p1: device busy
[INFO]   dmsetup pass 2/3: removing ['nbd0p1']
[INFO]   Removed: nbd0p1
[INFO]   Evidence dm entries cleared

══════════════════════════════════════════════════════
  Unmount complete
══════════════════════════════════════════════════════
```

> The "device busy" warning on pass 1 is normal — the kernel needs a brief moment after NBD disconnect before the device mapper entry releases. Pass 2 always catches it.

---

## Troubleshooting

### "No forensic images found"

Check that your directory structure has host subdirectories:
```
evidence_root/
  Hostname/       ← required
    image.E01
```
If images are directly in the root, the root directory name is used as the hostname.

### NBD slots exhausted

```
[ERROR] All 16 NBD slots in use
```

Increase the slot count:
```bash
sudo python3 mount_evidence.py --nbd-max 32 /evidence/...
```

Or set permanently:
```bash
echo "options nbd nbds_max=32 max_part=0" | sudo tee /etc/modprobe.d/nbd.conf
sudo update-initramfs -u
```

### LVM volumes not mounting

Run with `-v` to see debug output. Common causes:

```bash
# Check what vgchange -ay activated
sudo lvs

# Check what's in /dev/mapper
ls /dev/mapper/

# Try mounting manually to see the exact error
sudo mount -t ext4 -o ro,noload /dev/mapper/<vg>-<lv> /mnt/test
```

### "duplicate PV" LVM error

This means `max_part` is not set to 0:
```bash
cat /sys/module/nbd/parameters/max_part   # should be 0
sudo rmmod nbd
sudo modprobe nbd nbds_max=32 max_part=0
```

### Unmount leaves entries in /dev/mapper

Run unmount manually:
```bash
sudo dmsetup ls | grep -v "^control" | awk '{print $1}' | \
  while read name; do sudo dmsetup remove --force "$name"; done
```

### Script crashes on corrupt Windows images

This is expected — corrupt NTFS directories produce `OSError: [Errno 5] Input/output error`. The script handles these gracefully with lazy unmounting (`umount -l`) and continues teardown. The corrupted data is visible via the raw block device even when the filesystem driver can't read it.

---

## Known Limitations

- **WSL not supported** — requires real Linux kernel with nbd, device mapper, loop, and FUSE support
- **LUKS encrypted partitions** — skipped; decryption key handling is out of scope
- **Linux RAID (mdadm)** — skipped; array assembly would be required
- **BitLocker** — NTFS partition mounts without decryption; encrypted files are unreadable
- **VMFS5** — vmfs6-fuse may or may not support VMFS5 depending on the build; VMFS6 is fully supported
- **VG name collisions** — if two seized hosts have identical LVM VG names and are mounted simultaneously, `vgchange -ay` will activate both under the same name. Work around by mounting one host at a time or using `--mount-base` to separate them
- **NBD max 32 slots** — for cases with more than 32 VMDKs simultaneously, increase `nbds_max` further. Values up to 128 are stable

---

## Log file

All operations are logged to `/var/log/mount_evidence.log` (or your custom `--log` path). The log always captures DEBUG level regardless of the `--verbose` flag, making post-incident review possible even when the console output was not saved.

```bash
# Watch live during a mount
tail -f /var/log/mount_evidence.log

# Review after the fact
grep "ERROR\|WARN" /var/log/mount_evidence.log
```

---

## License

MIT — use freely, attribution appreciated.

---

*ForensicMounter — built for incident response, tested against real vCenter evidence.*
