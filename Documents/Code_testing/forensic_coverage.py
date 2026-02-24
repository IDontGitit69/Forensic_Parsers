#!/usr/bin/env python3
"""
forensic_coverage.py — Windows Forensic Artifact Coverage Analyzer
Scans a mounted Windows image and reports date ranges for every major artifact.

Usage:
    python3 forensic_coverage.py /mnt/image [--json] [--out report.txt]

Requirements (SIFT Workstation):
    evtxexport, rip.pl (regripper), exiftool, sqlite3, strings
    Python stdlib only (no pip deps)
"""

import argparse
import datetime
import json
import os
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def run(cmd, timeout=60, input_data=None):
    """Run a shell command and return stdout."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout, input=input_data
        )
        return r.stdout
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

def run_sudo(cmd, timeout=60):
    return run(f"sudo {cmd}", timeout=timeout)

def find_files(base, pattern, maxdepth=None):
    """Return list of paths matching pattern under base."""
    depth = f"-maxdepth {maxdepth}" if maxdepth else ""
    out = run_sudo(f'find "{base}" {depth} -iname "{pattern}" -type f 2>/dev/null')
    return [p.strip() for p in out.strip().split('\n') if p.strip()]

def parse_iso(s):
    """Try to parse an ISO-ish timestamp string to date."""
    s = s.strip()
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(s[:len(fmt)+5].rstrip('Z'), fmt)
        except Exception:
            pass
    return None

def filetime_to_dt(raw_bytes):
    """Convert 8-byte Windows FILETIME to datetime."""
    try:
        ts = struct.unpack('<Q', raw_bytes)[0]
        if ts == 0:
            return None
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ts // 10)
    except Exception:
        return None

def date_range(dates):
    """Return (min, max) from a list of datetime objects, filtering None."""
    valid = [d for d in dates if d is not None]
    if not valid:
        return None, None
    return min(valid), max(valid)

def fmt_range(mn, mx, count=None):
    d = f"{mn.strftime('%Y-%m-%d')} → {mx.strftime('%Y-%m-%d')}" if mn and mx else "no data"
    if count is not None:
        d += f"  ({count:,} events)"
    return d

BOLD  = "\033[1m"
CYAN  = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED   = "\033[31m"
RESET = "\033[0m"
DIM   = "\033[2m"

def hdr(title):
    bar = "─" * (len(title) + 4)
    print(f"\n{CYAN}{BOLD}┌{bar}┐")
    print(f"│  {title}  │")
    print(f"└{bar}┘{RESET}")

def row(label, value, note="", color=None):
    c = color or ""
    print(f"  {BOLD}{label:<42}{RESET} {c}{value}{RESET}  {DIM}{note}{RESET}")


# ─────────────────────────────────────────────
#  1. EVENT LOGS
# ─────────────────────────────────────────────

INTERESTING_LOGS = [
    ("Security",          "Logons, account changes, privilege use"),
    ("System",            "Boot/shutdown, services, driver loads"),
    ("Application",       "App crashes, installs, errors"),
    ("Windows PowerShell","PowerShell execution"),
    ("Microsoft-Windows-TaskScheduler%4Operational",              "Scheduled task execution"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational", "RDP/interactive sessions"),
    ("Microsoft-Windows-User Profile Service%4Operational",       "Profile loads per logon"),
    ("Microsoft-Windows-NetworkProfile%4Operational",             "Network connections"),
    ("Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall", "Firewall changes"),
    ("Microsoft-Windows-Bits-Client%4Operational",                "Background downloads"),
    ("Microsoft-Windows-DriverFrameworks-UserMode%4Operational",  "USB device connections"),
    ("Microsoft-Windows-WindowsUpdateClient%4Operational",        "Windows Update"),
    ("Microsoft-Windows-GroupPolicy%4Operational",                "Group Policy application"),
    ("Microsoft-Windows-Winlogon%4Operational",                   "Winlogon events"),
    ("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational", "RDP core events"),
    ("Microsoft-Windows-Wlan-AutoConfig%4Operational",            "WiFi connections"),
    ("OAlerts",           "Office alerts"),
]

def analyze_evtx(image_root):
    results = []
    logdir = Path(image_root) / "Windows" / "System32" / "winevt" / "Logs"
    if not logdir.exists():
        return results

    for logname, desc in INTERESTING_LOGS:
        evtx = logdir / f"{logname}.evtx"
        if not evtx.exists():
            continue
        xml = run_sudo(f'evtxexport -f xml "{evtx}"', timeout=120)
        timestamps = re.findall(r'SystemTime="(\d{4}-\d{2}-\d{2}T[^"]+)"', xml)
        dts = [parse_iso(t) for t in timestamps]
        mn, mx = date_range(dts)
        count = len([d for d in dts if d])
        results.append({
            "name": logname.replace("%4", "/"),
            "desc": desc,
            "first": mn,
            "last": mx,
            "count": count,
            "path": str(evtx),
        })
    return results


# ─────────────────────────────────────────────
#  2. REGISTRY HIVES
# ─────────────────────────────────────────────

def get_hive_timestamps(hive_path, timeout=90):
    """Extract key last-write timestamps from a registry hive using multiple methods."""
    dts = []

    # Method 1: rip.pl regtime — "Thu Jan 25 04:19:00 2014 Z  KeyName"
    out = run_sudo(f'rip.pl -r {repr(hive_path)} -p regtime 2>/dev/null', timeout=timeout)
    for ts in re.findall(r'\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}', out):
        try:
            dt = datetime.datetime.strptime(ts.strip(), '%a %b %d %H:%M:%S %Y')
            dts.append(dt)
        except Exception:
            pass
    # ISO timestamps in regtime output
    for ts in re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', out):
        dt = parse_iso(ts)
        if dt:
            dts.append(dt)

    # Method 2: regfexport — "Last written time: Feb 05, 2014 17:42:12.xxx UTC"
    if not dts:
        out2 = run_sudo(f'regfexport {repr(hive_path)} - 2>/dev/null', timeout=timeout)
        for ts in re.findall(
            r'Last written time:\s+(\w+ \d+, \d{4} \d{2}:\d{2}:\d{2})', out2
        ):
            try:
                dt = datetime.datetime.strptime(ts.strip(), '%b %d, %Y %H:%M:%S')
                dts.append(dt)
            except Exception:
                pass

    return dts

def analyze_registry(image_root):
    results = []
    config = Path(image_root) / "Windows" / "System32" / "config"

    hives = {
        "SOFTWARE":  ("HKLM\\SOFTWARE",  "Installed software, Run keys, network config"),
        "SYSTEM":    ("HKLM\\SYSTEM",    "Services, USB history, ShimCache, timezone"),
        "SAM":       ("HKLM\\SAM",       "Local user accounts, password hashes, last login"),
        "SECURITY":  ("HKLM\\SECURITY",  "LSA secrets, cached domain credentials"),
    }

    for fname, (hive, desc) in hives.items():
        fpath = config / fname
        if not fpath.exists():
            continue
        dts = get_hive_timestamps(str(fpath))
        mn, mx = date_range(dts)
        results.append({
            "name": hive,
            "desc": desc,
            "first": mn,
            "last": mx,
            "count": len(dts),
            "path": str(fpath),
        })

    # User NTUSERs
    users_dir = Path(image_root) / "USERS"
    if not users_dir.exists():
        users_dir = Path(image_root) / "Users"
    if users_dir.exists():
        for user_dir in sorted(users_dir.iterdir()):
            ntuser = user_dir / "NTUSER.DAT"
            if not ntuser.exists():
                continue
            dts = get_hive_timestamps(str(ntuser))
            mn, mx = date_range(dts)
            results.append({
                "name": f"NTUSER ({user_dir.name})",
                "desc": "Run keys, UserAssist, RecentDocs, TypedURLs, MRU, typed paths",
                "first": mn,
                "last": mx,
                "count": len(dts),
                "path": str(ntuser),
            })

    return results


# ─────────────────────────────────────────────
#  3. SHIMCACHE (Program Execution)
# ─────────────────────────────────────────────

def analyze_shimcache(image_root):
    system_hive = Path(image_root) / "Windows" / "System32" / "config" / "SYSTEM"
    if not system_hive.exists():
        return None
    out = run_sudo(f'rip.pl -r "{system_hive}" -p appcompatcache 2>/dev/null', timeout=60)
    timestamps = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', out)
    executed = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?Executed', out)
    dts = [parse_iso(t) for t in timestamps]
    exec_dts = [parse_iso(t) for t in executed]
    mn, mx = date_range(dts)
    # Pull out unique interesting executables
    interesting = re.findall(
        r'(C:\\Users\\[^\\]+\\[^\s]+\.exe|C:\\[^W][^\s]+\.exe)',
        out, re.IGNORECASE
    )
    return {
        "name": "ShimCache (AppCompatCache)",
        "desc": "File modification times of executables that touched the system",
        "first": mn,
        "last": mx,
        "count": len(dts),
        "executed_count": len(exec_dts),
        "interesting": list(set(interesting))[:20],
        "path": str(system_hive),
    }


# ─────────────────────────────────────────────
#  4. PREFETCH
# ─────────────────────────────────────────────

def analyze_prefetch(image_root):
    pf_dir = Path(image_root) / "Windows" / "Prefetch"
    if not pf_dir.exists():
        return None
    pf_files = list(pf_dir.glob("*.pf"))
    if not pf_files:
        return None

    timestamps = []
    for pf in pf_files:
        st = run_sudo(f'stat --format="%Y" "{pf}"').strip()
        try:
            dt = datetime.datetime.utcfromtimestamp(int(st))
            timestamps.append(dt)
        except Exception:
            pass

    mn, mx = date_range(timestamps)
    return {
        "name": "Prefetch",
        "desc": "Program execution (last run time from file mtime)",
        "first": mn,
        "last": mx,
        "count": len(pf_files),
        "path": str(pf_dir),
        "note": "⚠️ Low count may indicate disabled/cleared prefetch" if len(pf_files) < 20 else "",
    }


# ─────────────────────────────────────────────
#  5. RECYCLE BIN
# ─────────────────────────────────────────────

def analyze_recycle_bin(image_root):
    rb_dir = Path(image_root) / "$RECYCLE.BIN"
    if not rb_dir.exists():
        return None

    # Run entire analysis as a single sudo Python process to avoid shell $-expansion
    script = f"""
import struct, datetime
from pathlib import Path

rb = Path({repr(str(rb_dir))})
for f in rb.rglob('*'):
    if not (f.is_file() and f.name.startswith('$I')):
        continue
    try:
        d = f.read_bytes()
        if len(d) < 28:
            continue
        path = d[24:].decode('utf-16-le', errors='replace').rstrip(chr(0))
        ts_raw = struct.unpack('<Q', d[16:24])[0]
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ts_raw//10)
        print(dt.strftime('%Y-%m-%d %H:%M:%S') + '|' + path)
    except Exception:
        pass
"""
    result = subprocess.run(
        ['sudo', 'python3', '-c', script],
        capture_output=True, text=True, timeout=30
    )

    entries = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if '|' not in line:
            continue
        ts_str, orig_path = line.split('|', 1)
        dt = parse_iso(ts_str)
        if dt:
            entries.append({"deleted": dt, "original_path": orig_path.strip()})

    if not entries:
        return None
    dts = [e["deleted"] for e in entries]
    mn, mx = date_range(dts)
    return {
        "name": "Recycle Bin ($RECYCLE.BIN)",
        "desc": "Deleted files with original paths and deletion timestamps",
        "first": mn,
        "last": mx,
        "count": len(entries),
        "entries": sorted(entries, key=lambda x: x["deleted"]),
        "path": str(rb_dir),
    }


# ─────────────────────────────────────────────
#  6. LNK / RECENT FILES
# ─────────────────────────────────────────────

def analyze_lnk(image_root):
    users_dir = Path(image_root) / "USERS"
    if not users_dir.exists():
        users_dir = Path(image_root) / "Users"

    all_lnk = find_files(str(image_root), "*.lnk")
    timestamps = []
    for lnk in all_lnk:
        st = run_sudo(f'stat --format="%Y" "{lnk}"').strip()
        try:
            dt = datetime.datetime.utcfromtimestamp(int(st))
            timestamps.append(dt)
        except Exception:
            pass

    mn, mx = date_range(timestamps)
    return {
        "name": "LNK / Recent Files",
        "desc": "Shortcut files revealing recently accessed files & folders",
        "first": mn,
        "last": mx,
        "count": len(all_lnk),
        "path": "USERS\\*/AppData\\Roaming\\Microsoft\\Windows\\Recent",
    }


# ─────────────────────────────────────────────
#  7. EMAIL (.eml)
# ─────────────────────────────────────────────

def analyze_email(image_root):
    eml_files = find_files(str(image_root), "*.eml")
    if not eml_files:
        return None

    dates = []
    accounts = set()
    for eml in eml_files:
        content = run_sudo(f'grep -m1 "^Date:" "{eml}"')
        date_str = content.replace("Date:", "").strip()
        if date_str:
            # Try to parse RFC 2822 date
            try:
                import email.utils
                ts = email.utils.parsedate_to_datetime(date_str)
                dates.append(ts.replace(tzinfo=None))
            except Exception:
                pass
        # Grab account dirs
        parts = eml.split(os.sep)
        for i, p in enumerate(parts):
            if "Windows Live Mail" in p or "Thunderbird" in p or "Mail" in p:
                if i + 1 < len(parts):
                    accounts.add(parts[i + 1])

    mn, mx = date_range(dates)
    return {
        "name": "Email (.eml)",
        "desc": "Locally cached email messages",
        "first": mn,
        "last": mx,
        "count": len(eml_files),
        "accounts": list(accounts)[:5],
        "path": "AppData\\Local\\Microsoft\\Windows Live Mail (or similar)",
    }


# ─────────────────────────────────────────────
#  8. BROWSER HISTORY
# ─────────────────────────────────────────────

def analyze_browser_history(image_root):
    results = []

    # ── IE History folders (folder names encode date range) ──
    ie_hist = run_sudo(f'find "{image_root}" -path "*/History.IE5/MSHist*" -type d 2>/dev/null')
    ie_dates = []
    for folder in ie_hist.strip().split('\n'):
        folder = folder.strip()
        m = re.search(r'MSHist01(\d{8})(\d{8})', folder)
        if m:
            try:
                ie_dates.append(datetime.datetime.strptime(m.group(1), '%Y%m%d'))
                ie_dates.append(datetime.datetime.strptime(m.group(2), '%Y%m%d'))
            except Exception:
                pass
    if ie_dates:
        mn, mx = date_range(ie_dates)
        results.append({
            "name": "Internet Explorer History",
            "desc": "Browsed URLs, search terms",
            "first": mn, "last": mx, "count": None,
            "path": "AppData\\Local\\Microsoft\\Windows\\History",
        })

    # ── Chrome (History SQLite) ──
    chrome_dbs = find_files(str(image_root), "History", maxdepth=None)
    chrome_dbs = [f for f in chrome_dbs if "Chrome" in f or "Google" in f]
    for db in chrome_dbs[:3]:
        out = run_sudo(f'sqlite3 "{db}" "SELECT MIN(last_visit_time), MAX(last_visit_time), COUNT(*) FROM urls;" 2>/dev/null')
        parts = out.strip().split('|')
        if len(parts) == 3:
            # Chrome uses microseconds since 1601-01-01
            try:
                def chrome_ts(v):
                    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(v))
                mn = chrome_ts(parts[0])
                mx = chrome_ts(parts[1])
                cnt = int(parts[2])
                results.append({
                    "name": "Chrome History",
                    "desc": "Browsed URLs, search terms, download history",
                    "first": mn, "last": mx, "count": cnt,
                    "path": db,
                })
            except Exception:
                pass

    # ── Firefox (places.sqlite) ──
    ff_dbs = find_files(str(image_root), "places.sqlite")
    for db in ff_dbs[:3]:
        out = run_sudo(f'sqlite3 "{db}" "SELECT MIN(last_visit_date), MAX(last_visit_date), COUNT(*) FROM moz_places WHERE last_visit_date IS NOT NULL;" 2>/dev/null')
        parts = out.strip().split('|')
        if len(parts) == 3:
            try:
                def ff_ts(v):
                    return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=int(v))
                mn = ff_ts(parts[0])
                mx = ff_ts(parts[1])
                cnt = int(parts[2])
                results.append({
                    "name": "Firefox History",
                    "desc": "Browsed URLs, bookmarks, downloads",
                    "first": mn, "last": mx, "count": cnt,
                    "path": db,
                })
            except Exception:
                pass

    return results


# ─────────────────────────────────────────────
#  9. USB DEVICES
# ─────────────────────────────────────────────

def analyze_usb(image_root):
    system_hive = Path(image_root) / "Windows" / "System32" / "config" / "SYSTEM"
    if not system_hive.exists():
        return None
    out = run_sudo(f'rip.pl -r "{system_hive}" -p usbstor 2>/dev/null', timeout=30)
    timestamps = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', out)
    dts = [parse_iso(t) for t in timestamps]
    mn, mx = date_range(dts)

    # Extract device names
    devices = re.findall(r'Disk&Ven_([^\[]+)\[', out)
    friendly = re.findall(r'FriendlyName\s+:\s+(.+)', out)
    sns = re.findall(r'S/N:\s+([^\s]+)', out)

    return {
        "name": "USB Devices (USBSTOR)",
        "desc": "USB storage devices connected to the system",
        "first": mn,
        "last": mx,
        "count": len(sns),
        "devices": [d.strip() for d in devices[:10]],
        "friendly_names": [f.strip() for f in friendly[:10]],
        "path": str(system_hive),
    }


# ─────────────────────────────────────────────
#  10. FILE SYSTEM OVERVIEW (MFT/NTFS stats)
# ─────────────────────────────────────────────

def analyze_filesystem(image_root):
    # Grab overall timestamp spread from user files
    out = run_sudo(
        f'find "{image_root}/USERS" -type f -not -path "*/Windows/*" '
        f'2>/dev/null | head -500 | xargs -I{{}} sudo stat --format="%Y" {{}} 2>/dev/null',
        timeout=30
    )
    timestamps = []
    for line in out.strip().split('\n'):
        try:
            timestamps.append(datetime.datetime.utcfromtimestamp(int(line.strip())))
        except Exception:
            pass

    mn, mx = date_range(timestamps)
    return {
        "name": "File System (NTFS mtime sample)",
        "desc": "File modification timestamps across user files (sample of 500)",
        "first": mn,
        "last": mx,
        "count": len(timestamps),
        "note": "⚠️ EWF packaging may have normalized timestamps to packaging date",
        "path": str(image_root),
    }


# ─────────────────────────────────────────────
#  11. SCHEDULED TASKS
# ─────────────────────────────────────────────

def analyze_scheduled_tasks(image_root):
    task_dir = Path(image_root) / "Windows" / "System32" / "Tasks"
    if not task_dir.exists():
        return None
    tasks = find_files(str(task_dir), "*")
    # Ignore directories
    task_files = [t for t in tasks if t.strip()]

    timestamps = []
    for t in task_files:
        st = run_sudo(f'stat --format="%Y" "{t}"').strip()
        try:
            timestamps.append(datetime.datetime.utcfromtimestamp(int(st)))
        except Exception:
            pass

    mn, mx = date_range(timestamps)
    return {
        "name": "Scheduled Tasks",
        "desc": "Scheduled task XML definitions",
        "first": mn,
        "last": mx,
        "count": len(task_files),
        "path": str(task_dir),
    }


# ─────────────────────────────────────────────
#  12. THUMBNAIL CACHE
# ─────────────────────────────────────────────

def analyze_thumbcache(image_root):
    dbs = find_files(str(image_root), "thumbcache_*.db")
    if not dbs:
        return None
    return {
        "name": "Thumbnail Cache",
        "desc": "Cached thumbnails — may contain images of deleted files",
        "first": None,
        "last": None,
        "count": len(dbs),
        "path": "AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db",
        "note": "Use thumbcache_viewer or extract raw JPEG headers to recover images",
    }


# ─────────────────────────────────────────────
#  13. USER ACCOUNTS (SAM)
# ─────────────────────────────────────────────

def analyze_user_accounts(image_root):
    sam = Path(image_root) / "Windows" / "System32" / "config" / "SAM"
    if not sam.exists():
        return None
    out = run_sudo(f'rip.pl -r "{sam}" -p samparse 2>/dev/null', timeout=30)
    users = re.findall(r'Username\s+:\s+(.+)', out)
    last_logins = re.findall(r'Last Login Date\s+:\s+(.+)', out)
    pwd_resets = re.findall(r'Pwd Reset Date\s+:\s+(.+)', out)
    created = re.findall(r'Account Created\s+:\s+(.+)', out)

    dts = []
    for d in last_logins + pwd_resets + created:
        dt = parse_iso(d.strip())
        if dt:
            dts.append(dt)
    mn, mx = date_range(dts)

    return {
        "name": "User Accounts (SAM)",
        "desc": "Local accounts, creation dates, last login times",
        "first": mn,
        "last": mx,
        "count": len([u for u in users if u.strip()]),
        "users": [u.strip() for u in users if u.strip()],
        "path": str(sam),
    }


# ─────────────────────────────────────────────
#  14. WINDOWS SEARCH INDEX
# ─────────────────────────────────────────────

def analyze_search_index(image_root):
    edb = find_files(str(image_root), "Windows.edb")
    if not edb:
        return None
    return {
        "name": "Windows Search Index (Windows.edb)",
        "desc": "Indexed file metadata — filenames, content snippets, email subjects",
        "first": None,
        "last": None,
        "count": len(edb),
        "path": edb[0] if edb else "",
        "note": "Use ESEDatabaseView or libesedb-tools to extract",
    }


# ─────────────────────────────────────────────
#  15. STICKY NOTES
# ─────────────────────────────────────────────

def analyze_sticky_notes(image_root):
    snts = find_files(str(image_root), "StickyNotes.snt")
    snts += find_files(str(image_root), "plum.sqlite")  # Win10
    if not snts:
        return None
    return {
        "name": "Sticky Notes",
        "desc": "User sticky note content (plaintext + RTF)",
        "first": None,
        "last": None,
        "count": len(snts),
        "path": snts[0] if snts else "",
        "note": "Extract with strings or parse RTF directly",
    }


# ─────────────────────────────────────────────
#  16. EXIF / PHOTO METADATA
# ─────────────────────────────────────────────

def analyze_exif(image_root):
    photos = find_files(str(image_root) + "/USERS", "*.jpg")
    photos += find_files(str(image_root) + "/USERS", "*.jpeg")
    photos += find_files(str(image_root) + "/USERS", "*.png")

    dts = []
    gps_count = 0
    for photo in photos[:50]:
        out = run_sudo(f'exiftool -DateTimeOriginal -CreateDate -GPSLatitude "{photo}" 2>/dev/null')
        for line in out.split('\n'):
            if 'Date' in line:
                m = re.search(r'(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})', line)
                if m:
                    dt_str = m.group(1).replace(':', '-', 2)
                    dt = parse_iso(dt_str)
                    if dt:
                        dts.append(dt)
            if 'GPS' in line and line.strip().split(':')[-1].strip():
                gps_count += 1

    mn, mx = date_range(dts)
    return {
        "name": "Photo EXIF Metadata",
        "desc": "Camera make/model, GPS coords, original capture timestamps",
        "first": mn,
        "last": mx,
        "count": len(photos),
        "gps_found": gps_count,
        "path": "USERS\\*/Pictures and Desktop",
    }


# ─────────────────────────────────────────────
#  17. USERASSIST
# ─────────────────────────────────────────────

def analyze_userassist(image_root):
    users_dir = Path(image_root) / "USERS"
    if not users_dir.exists():
        users_dir = Path(image_root) / "Users"
    if not users_dir.exists():
        return []

    results = []
    for user_dir in sorted(users_dir.iterdir()):
        ntuser = user_dir / "NTUSER.DAT"
        if not ntuser.exists():
            continue
        out = run_sudo(f'rip.pl -r "{ntuser}" -p userassist 2>/dev/null', timeout=30)
        timestamps = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', out)
        dts = [parse_iso(t) for t in timestamps]
        mn, mx = date_range(dts)
        results.append({
            "name": f"UserAssist ({user_dir.name})",
            "desc": "GUI program execution with run counts and last run times",
            "first": mn,
            "last": mx,
            "count": len(dts),
            "path": str(ntuser),
        })
    return results


# ─────────────────────────────────────────────
#  18. NETWORK PROFILES
# ─────────────────────────────────────────────

def analyze_network_profiles(image_root):
    soft = Path(image_root) / "Windows" / "System32" / "config" / "SOFTWARE"
    if not soft.exists():
        return None
    out = run_sudo(f'rip.pl -r "{soft}" -p networklist 2>/dev/null', timeout=30)
    timestamps = re.findall(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', out)
    dts = [parse_iso(t) for t in timestamps]
    networks = re.findall(r'Profile Name\s+:\s+(.+)', out)
    mn, mx = date_range(dts)
    return {
        "name": "Network Profiles (NetworkList)",
        "desc": "Previously connected networks (WiFi SSIDs, Ethernet)",
        "first": mn,
        "last": mx,
        "count": len(networks),
        "networks": [n.strip() for n in networks[:10]],
        "path": str(soft),
    }


# ─────────────────────────────────────────────
#  OUTPUT
# ─────────────────────────────────────────────

def print_artifact(a):
    if not a:
        return
    mn, mx = a.get("first"), a.get("last")
    count = a.get("count")

    if mn and mx:
        date_str = f"{GREEN}{mn.strftime('%Y-%m-%d')} → {mx.strftime('%Y-%m-%d')}{RESET}"
        color = GREEN
    else:
        date_str = f"{YELLOW}no timestamps extracted{RESET}"
        color = YELLOW

    cnt_str = f"({count:,} items)" if count is not None else ""
    print(f"\n  {BOLD}{CYAN}{a['name']}{RESET}")
    print(f"  {'─'*60}")
    print(f"  {BOLD}Range  :{RESET} {date_str}  {DIM}{cnt_str}{RESET}")
    print(f"  {BOLD}Covers :{RESET} {a['desc']}")
    if a.get('note'):
        print(f"  {BOLD}Note   :{RESET} {YELLOW}{a['note']}{RESET}")
    if a.get('path'):
        print(f"  {BOLD}Path   :{RESET} {DIM}{a['path']}{RESET}")
    # Extra details
    if a.get('users'):
        print(f"  {BOLD}Users  :{RESET} {', '.join(a['users'])}")
    if a.get('devices'):
        print(f"  {BOLD}Devices:{RESET} {', '.join(a['devices'][:5])}")
    if a.get('networks'):
        print(f"  {BOLD}Networks:{RESET} {', '.join(a['networks'][:5])}")
    if a.get('accounts'):
        print(f"  {BOLD}Accts  :{RESET} {', '.join(a['accounts'][:5])}")
    if a.get('gps_found'):
        print(f"  {BOLD}GPS    :{RESET} {RED}{a['gps_found']} photos with GPS data!{RESET}")


def print_coverage_chart(all_artifacts):
    # Collect all valid date ranges
    all_dates = []
    for a in all_artifacts:
        if isinstance(a, list):
            for item in a:
                if item.get('first'):
                    all_dates.append(item['first'])
                if item.get('last'):
                    all_dates.append(item['last'])
        elif a and a.get('first'):
            all_dates.append(a['first'])
            if a.get('last'):
                all_dates.append(a['last'])

    if not all_dates:
        return

    global_min = min(all_dates)
    global_max = max(all_dates)
    span = (global_max - global_min).days or 1

    hdr("COVERAGE TIMELINE")
    print(f"  Overall span: {BOLD}{global_min.strftime('%Y-%m-%d')} → {global_max.strftime('%Y-%m-%d')}{RESET}  ({span} days)\n")

    WIDTH = 50

    def bar(mn, mx):
        if not mn or not mx:
            return " " * WIDTH + "  (no data)"
        start = max(0, int((mn - global_min).days / span * WIDTH))
        end   = min(WIDTH, int((mx - global_min).days / span * WIDTH) + 1)
        b = "·" * start + "█" * (end - start) + "·" * (WIDTH - end)
        return f"{b}  {mn.strftime('%Y-%m-%d')} → {mx.strftime('%Y-%m-%d')}"

    def print_bar(label, mn, mx):
        print(f"  {label:<36} {GREEN}{bar(mn, mx)}{RESET}")

    # Print bars for all artifacts
    for a in all_artifacts:
        if isinstance(a, list):
            for item in a:
                print_bar(item['name'][:35], item.get('first'), item.get('last'))
        elif a:
            print_bar(a['name'][:35], a.get('first'), a.get('last'))

    # Timeline axis
    print(f"\n  {'':36} {global_min.strftime('%Y-%m-%d')}{'':<{WIDTH-20}}{global_max.strftime('%Y-%m-%d')}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Windows Forensic Artifact Coverage Analyzer"
    )
    parser.add_argument("mount_point", help="Path to mounted Windows image (e.g. /mnt/image)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--out", help="Save report to file")
    args = parser.parse_args()

    image_root = args.mount_point.rstrip('/')
    if not os.path.isdir(image_root):
        print(f"{RED}[!] Mount point not found: {image_root}{RESET}")
        sys.exit(1)

    print(f"\n{BOLD}{CYAN}{'='*68}")
    print(f"  🔍  FORENSIC ARTIFACT COVERAGE REPORT")
    print(f"  Image root : {image_root}")
    print(f"  Run time   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*68}{RESET}")

    results = {}

    # ── Run all analyzers ──
    hdr("EVENT LOGS")
    evtx = analyze_evtx(image_root)
    results['event_logs'] = evtx
    for a in evtx:
        print_artifact(a)

    hdr("REGISTRY HIVES")
    reg = analyze_registry(image_root)
    results['registry'] = reg
    for a in reg:
        print_artifact(a)

    hdr("PROGRAM EXECUTION")
    shim = analyze_shimcache(image_root)
    pf   = analyze_prefetch(image_root)
    ua   = analyze_userassist(image_root)
    results['shimcache'] = shim
    results['prefetch']  = pf
    results['userassist'] = ua
    print_artifact(shim)
    print_artifact(pf)
    for a in ua:
        print_artifact(a)

    hdr("FILE & DELETION ARTIFACTS")
    rb  = analyze_recycle_bin(image_root)
    lnk = analyze_lnk(image_root)
    results['recycle_bin'] = rb
    results['lnk'] = lnk
    print_artifact(lnk)
    print_artifact(rb)
    if rb and rb.get('entries'):
        print(f"\n  {BOLD}Deleted files:{RESET}")
        for e in rb['entries']:
            print(f"    {DIM}{e['deleted'].strftime('%Y-%m-%d %H:%M')}  {e['original_path']}{RESET}")

    hdr("BROWSER ARTIFACTS")
    browsers = analyze_browser_history(image_root)
    results['browser'] = browsers
    for a in browsers:
        print_artifact(a)

    hdr("EMAIL")
    email_a = analyze_email(image_root)
    results['email'] = email_a
    print_artifact(email_a)

    hdr("USB DEVICES")
    usb = analyze_usb(image_root)
    results['usb'] = usb
    print_artifact(usb)

    hdr("NETWORK")
    net = analyze_network_profiles(image_root)
    results['network'] = net
    print_artifact(net)

    hdr("USER ACCOUNTS")
    accounts = analyze_user_accounts(image_root)
    results['accounts'] = accounts
    print_artifact(accounts)

    hdr("OTHER ARTIFACTS")
    st   = analyze_scheduled_tasks(image_root)
    tc   = analyze_thumbcache(image_root)
    sn   = analyze_sticky_notes(image_root)
    exif = analyze_exif(image_root)
    si   = analyze_search_index(image_root)
    fs   = analyze_filesystem(image_root)
    for a in [st, tc, sn, exif, si, fs]:
        results[a['name'] if a else 'skip'] = a
        print_artifact(a)

    # ── Coverage timeline ──
    all_artifacts = (
        evtx + reg + [shim, pf] + ua + [rb, lnk] +
        browsers + ([email_a] if email_a else []) +
        [usb, net, accounts, st, fs]
    )
    print_coverage_chart(all_artifacts)

    # ── Gaps summary ──
    hdr("GAPS & INVESTIGATIVE NOTES")
    gaps = []
    if not evtx:
        gaps.append("No event logs found")
    elif not any(a['name'] == 'Security' and a['first'] for a in evtx):
        gaps.append("Security log has no timestamps")
    if not browsers:
        gaps.append("No browser history found")
    if pf and pf.get('count', 99) < 20:
        gaps.append(f"Prefetch sparse ({pf['count']} files) — may be disabled or cleared")
    if not email_a:
        gaps.append("No local email found")
    if usb and usb.get('count', 0) > 0:
        gaps.append(f"USB devices found ({usb['count']}) — physical devices are key evidence")
    for a in reg:
        if 'NTUSER' in a['name'] and not a.get('first'):
            gaps.append(f"NTUSER.DAT for {a['name']} has no timestamps — profile may be empty")
    if not gaps:
        gaps.append("No major gaps detected")

    for g in gaps:
        icon = "⚠️ " if any(word in g.lower() for word in ["sparse","cleared","disabled","no ","empty"]) else "ℹ️ "
        print(f"  {icon} {g}")

    # ── JSON output ──
    if args.json:
        def dt_serial(obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            return str(obj)
        print("\n\n" + json.dumps(results, default=dt_serial, indent=2))

    if args.out:
        # Strip ANSI for file output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        # Re-run to file by capturing stdout — just note the path
        print(f"\n  {DIM}(to save clean output: python3 forensic_coverage.py {image_root} | sed 's/\\x1b\\[[0-9;]*m//g' > {args.out}){RESET}")

    print(f"\n{BOLD}{CYAN}{'='*68}")
    print(f"  Analysis complete — {datetime.datetime.utcnow().strftime('%H:%M:%S')} UTC")
    print(f"{'='*68}{RESET}\n")


if __name__ == "__main__":
    main()
