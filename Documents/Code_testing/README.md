# vmdk-sesparse-merger

A Bash utility for merging VMware sesparse snapshot deltas into a single, self-contained VMDK — making snapshot data fully readable without needing a live VMware environment.

---

## The Problem

When VMware takes a snapshot of a virtual machine, it does not modify the original disk image. Instead it creates a **snapshot descriptor** and a **sesparse extent file** that records only the *changes* made to the disk since the snapshot was taken. The original base disk remains frozen underneath.

This delta-based structure looks like this on disk:

```
image1.vmdk              ← base descriptor
image1-flat.vmdk         ← base flat extent (the original disk data)
image1-000001.vmdk       ← snapshot descriptor
image1-000001-sesparse.vmdk  ← sesparse delta (changes since snapshot)
```

The sesparse format is a **space-efficient sparse** container — it only stores sectors that were actually written after the snapshot. To read the full disk as it appeared at snapshot time, you need to resolve both the sesparse delta *and* the base flat extent together.

This presents a problem when you want to:

- Mount and inspect a snapshot outside of VMware
- Recover data from a decommissioned VM
- Ingest a snapshot image into another tool (forensics, backup, analysis)

Most tools cannot natively resolve a sesparse chain. You need to **flatten** the snapshot delta back into a single coherent VMDK first.

---

## What This Script Does

`merge_sesparse.sh` automates the full resolution and merge process across an entire directory of VMDK files. It:

1. **Scans** the source directory and identifies descriptor files by reading their contents (looks for `# Disk DescriptorFile` in the first line) — not by filename pattern alone
2. **Classifies** each descriptor as either a snapshot descriptor (sesparse extent) or a base descriptor (flat extent)
3. **Pairs** each snapshot descriptor to its base descriptor using the `parentFileNameHint` field embedded in the descriptor file itself
4. **Merges** the full snapshot chain into a single output VMDK using `qemu-img`
5. **Moves** the base flat extent into the output directory alongside the merged file
6. **Runs all jobs in parallel** up to a configurable limit
7. **Logs** every step with timestamps to a `merge.log` file in the output directory

The result is a `./merged/` directory containing a fully resolved VMDK and its flat extent, ready to mount or process with any standard tool.

```
merged/
  image1.vmdk          ← merged snapshot chain (sesparse delta resolved)
  image1-flat.vmdk     ← base flat extent (moved from source)
  merge.log            ← full run log with timestamps
```

---

## Requirements

- **Linux** or **macOS** (WSL2 on Windows works but see the [Performance Notes](#performance-notes) section)
- **`qemu-img`** — part of the `qemu-utils` package

Install on Debian/Ubuntu:
```bash
sudo apt install qemu-utils
```

Install on RHEL/Fedora:
```bash
sudo dnf install qemu-img
```

Install on macOS (Homebrew):
```bash
brew install qemu
```

Optionally, **GNU `parallel`** for more robust parallel job management:
```bash
sudo apt install parallel   # Debian/Ubuntu
brew install parallel       # macOS
```

If `parallel` is not installed the script falls back to native Bash background job management automatically.

---

## Usage

```bash
# Run from the directory containing your VMDKs
./merge_sesparse.sh

# Or point it at a directory explicitly
./merge_sesparse.sh /path/to/vmdk/directory
```

Make sure the script is executable first:
```bash
chmod +x merge_sesparse.sh
```

### Output

All merged files are written to `<source_directory>/merged/`. The source directory is not modified except that flat extent files are **moved** (not copied) into the output directory to avoid duplicating potentially very large files.

---

## Configuration

At the top of the script there are two variables you can adjust:

```bash
MAX_PARALLEL=4   # Number of concurrent merge jobs
```

Increase this on machines with fast NVMe storage and many CPU cores. Decrease it (even to `1`) if your disks are spinning HDDs or you are running over a network share, where parallel IO will hurt more than it helps.

---

## How the Pairing Works

The script does not rely on filename conventions to match snapshot descriptors to their base descriptors. Instead it reads the descriptor files themselves:

**Snapshot descriptor** (`image1-000001.vmdk`) contains:
```
parentFileNameHint="image1.vmdk"
```

This tells the script exactly which base descriptor to pair it with. The base descriptor (`image1.vmdk`) is then parsed for its extent line:
```
RW 4194304 FLAT "image1-flat.vmdk"
```

Which tells the script which flat extent file to move into the output directory. This content-driven approach means the script works correctly regardless of naming conventions or snapshot depth numbering.

---

## Log Output

A timestamped log is written to `merged/merge.log`. During the run you will see output like:

```
============================================
 VMDK Sesparse Merger - Mon Jun  3 10:22:01 2026
 Source:  /data/vmdks
 Output:  /data/vmdks/merged
============================================

[INFO] Scanning for VMDK descriptor files in: /data/vmdks

[DESC]  10:22:01 | Snapshot descriptor: image1-000001.vmdk  (extent: image1-000001-sesparse.vmdk)
[DESC]  10:22:01 | Base descriptor:     image1.vmdk  (extent: image1-flat.vmdk)

[INFO] Pairing snapshot descriptors with base descriptors...

[PAIR]  10:22:01 | image1-000001.vmdk  ->  image1.vmdk

[INFO] Found 1 pair(s) to process.
[INFO] Starting merge (max 4 parallel jobs)...

[START] 10:22:01 | image1-000001.vmdk  ->  /data/vmdks/merged/image1.vmdk
[DONE]  10:24:38 | image1-000001.vmdk -> merged/image1.vmdk | Size: 42G | Elapsed: 157s
[MOVE]  10:24:38 | image1-flat.vmdk  ->  merged/image1-flat.vmdk
[MOVE]  10:24:38 | Done | image1-flat.vmdk | Size: 80G

============================================
 Complete - Mon Jun  3 10:24:38 2026
 Pairs processed: 1
 Succeeded:       1
 Failed:          0
 Output dir:      /data/vmdks/merged/
============================================
```

---

## Performance Notes

**Sesparse is inherently slow to resolve.** Unlike a flat extent which is read sequentially, a sesparse file must be walked block by block to determine which sectors contain written data vs sparse (empty) regions. For large disks with heavy write activity since the snapshot, this can take a significant amount of time. This is a characteristic of the format, not a limitation of the script.

**WSL2 on Windows** will work but comes with an important caveat: if your VMDK files live on a Windows drive (anywhere under `/mnt/c/`, `/mnt/d/`, etc.) every read and write crosses the WSL↔Windows filesystem boundary via the 9P protocol driver, which can be 10–20x slower than native Linux IO. If you are processing large VMDKs under WSL2, copy them into the WSL native filesystem first (`/home/youruser/`) before running the script — the difference is substantial.

**Parallel jobs vs IO:** `MAX_PARALLEL=4` is a reasonable default for SSDs. If your source files live on spinning disks or a NAS, reduce this to `1` or `2`. Parallel random IO on a spinning disk will serialize anyway and the overhead of context switching makes it slower overall.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All pairs merged successfully |
| `1` | One or more merges failed, or no valid pairs found |

---

## License

MIT — do whatever you want with it.
