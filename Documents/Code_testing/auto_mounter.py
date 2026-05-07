import subprocess
import time
import sys
from pathlib import Path

AIM_CLI = r"C:\path\to\aim_cli.exe"
IMAGE_LIST = r"C:\path\to\images.txt"

def mount_images(image_list_path):
    images = []
    
    # Read and clean the image list
    with open(image_list_path) as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            images.append(line)
    
    if not images:
        print("No images found in list.")
        return
    
    print(f"Found {len(images)} images to mount.\n")
    
    for i, image in enumerate(images, 1):
        print(f"[{i}/{len(images)}] Mounting: {image}")
        
        # Verify the file exists before attempting mount
        if not Path(image).exists():
            print(f"  WARNING: File not found, skipping.\n")
            continue
        
        cmd = [
            AIM_CLI,
            "--pro",
            "--mountfs",
            "--readonly",
            f"--filename={image}",
            "--background"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"  SUCCESS: Mounted.\n")
        else:
            print(f"  ERROR: Mount failed.")
            print(f"  STDOUT: {result.stdout}")
            print(f"  STDERR: {result.stderr}\n")
        
        # Brief pause between mounts
        time.sleep(2)
    
    print("Bulk mount complete.")

if __name__ == "__main__":
    list_path = sys.argv[1] if len(sys.argv) > 1 else IMAGE_LIST
    mount_images(list_path)
