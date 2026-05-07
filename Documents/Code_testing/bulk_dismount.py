import subprocess
import sys
import time
import signal
from pathlib import Path

AIM_CLI = r"C:\path\to\aim_cli.exe"
DRIVE_LIST = r"C:\path\to\drives.txt"

def signal_handler(sig, frame):
    print("\nInterrupted by user. Exiting cleanly.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def dismount_images(drive_list_path):
    drives = []

    with open(drive_list_path) as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            drives.append(line)

    if not drives:
        print("No drive letters found in list.")
        return

    print(f"Found {len(drives)} drives to dismount.\n")

    for i, drive in enumerate(drives, 1):
        print(f"[{i}/{len(drives)}] Dismounting: {drive}")

        cmd = [
            AIM_CLI,
            "--pro",
            f"--dismountfs={drive}",
        ]

        subprocess.Popen(cmd)
        print(f"  SUCCESS: Dismount command sent.\n")

        time.sleep(2)

    print("Bulk dismount complete.")

if __name__ == "__main__":
    list_path = sys.argv[1] if len(sys.argv) > 1 else DRIVE_LIST
    dismount_images(list_path)
