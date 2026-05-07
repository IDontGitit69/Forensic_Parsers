import os
import sys
import struct
from pathlib import Path

# Minimum file size to be considered a valid image (50MB)
# Filters out descriptor VMDKs and tiny placeholder files
MIN_IMAGE_SIZE_MB = 50
MIN_IMAGE_SIZE_BYTES = MIN_IMAGE_SIZE_MB * 1024 * 1024

# Extensions to consider - first pass filter
IMAGE_EXTENSIONS = {
    '.vmdk', '.dd', '.raw', '.img', '.e01', '.ewf', '.aff',
    '.E01', '.EWF', '.AFF'  # case variants
}

# Magic bytes for formats that have them
MAGIC_SIGNATURES = {
    'VMDK_SPARSE': (0, b'\x4b\x44\x4d\x56'),   # KDMV
    'VMDK_COWD':   (0, b'\x44\x57\x4f\x43'),   # COWD  
    'EWF_E01':     (0, b'\x45\x56\x46\x09\x0d\x0a\xff\x00'),  # EVF
    'AFF':         (0, b'\x41\x46\x46'),         # AFF
}

# Extensions that rely purely on magic bytes (not size)
MAGIC_ONLY_EXTENSIONS = {'.e01', '.E01', '.ewf', '.EWF', '.aff', '.AFF'}

# Raw/unstructured formats validated by size only
SIZE_VALIDATED_EXTENSIONS = {'.dd', '.raw', '.img'}


def read_header(filepath, num_bytes=16):
    """Read the first N bytes of a file for magic byte inspection."""
    try:
        with open(filepath, 'rb') as f:
            return f.read(num_bytes)
    except (IOError, PermissionError) as e:
        print(f"  WARNING: Cannot read {filepath} - {e}")
        return None


def is_vmdk_descriptor(filepath):
    """
    VMDK descriptor files are small text files pointing to the actual data.
    Real sparse VMDKs start with KDMV magic.
    Flat VMDKs (-flat.vmdk) are large raw files with no magic.
    """
    header = read_header(filepath)
    if header is None:
        return False
    
    # Check for sparse VMDK magic (KDMV or COWD)
    if header[:4] in (b'\x4b\x44\x4d\x56', b'\x44\x57\x4f\x43'):
        return False  # This is a real sparse VMDK, not a descriptor
    
    # Check if it looks like a text descriptor file
    try:
        text = header.decode('ascii', errors='strict')
        if '# Disk DescriptorFile' in text or 'encoding=' in text or 'version=' in text:
            return True  # This is a descriptor file
    except (UnicodeDecodeError, ValueError):
        pass
    
    # If no magic and not text, check size
    size = os.path.getsize(filepath)
    if size < MIN_IMAGE_SIZE_BYTES:
        return True  # Too small to be a real image, likely descriptor
    
    return False


def validate_image(filepath):
    """
    Returns (is_valid, reason) tuple.
    Two layer validation - extension then magic/size.
    """
    path = Path(filepath)
    ext = path.suffix.lower()
    size = os.path.getsize(filepath)
    
    # --- VMDK specific handling ---
    if ext == '.vmdk':
        if is_vmdk_descriptor(filepath):
            return False, "VMDK descriptor file (not actual disk data)"
        
        header = read_header(filepath)
        if header is None:
            return False, "Cannot read file"
        
        # Sparse VMDK - has magic bytes
        if header[:4] in (b'\x4b\x44\x4d\x56', b'\x44\x57\x4f\x43'):
            return True, "Valid sparse VMDK (magic bytes confirmed)"
        
        # Flat VMDK - no magic, validate by size and name
        if '-flat' in path.name.lower() or size >= MIN_IMAGE_SIZE_BYTES:
            return True, f"Valid flat VMDK (size: {size / (1024**3):.2f} GB)"
        
        return False, f"VMDK too small to be a disk image ({size / (1024**2):.1f} MB)"
    
    # --- Magic byte validated formats ---
    if ext in {'.e01', '.ewf'}:
        header = read_header(filepath)
        if header and header[:3] == b'\x45\x56\x46':
            return True, "Valid E01/EWF (magic bytes confirmed)"
        return False, "E01/EWF magic bytes not found"
    
    if ext == '.aff':
        header = read_header(filepath)
        if header and header[:3] == b'\x41\x46\x46':
            return True, "Valid AFF (magic bytes confirmed)"
        return False, "AFF magic bytes not found"
    
    # --- Size validated formats (dd, raw, img) ---
    if ext in {'.dd', '.raw', '.img'}:
        if size >= MIN_IMAGE_SIZE_BYTES:
            return True, f"Valid raw image (size: {size / (1024**3):.2f} GB)"
        return False, f"Too small to be a disk image ({size / (1024**2):.1f} MB)"
    
    return False, "Unrecognized format"


def find_images(search_dir, output_file):
    """
    Recursively search for forensic images and write valid paths to output file.
    """
    search_path = Path(search_dir)
    
    if not search_path.exists():
        print(f"ERROR: Search directory does not exist: {search_dir}")
        sys.exit(1)
    
    print(f"Searching: {search_dir}")
    print(f"Minimum image size: {MIN_IMAGE_SIZE_MB}MB")
    print(f"Output file: {output_file}\n")
    print("-" * 60)
    
    valid_images = []
    skipped = []
    
    # Recursive walk
    for root, dirs, files in os.walk(search_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            ext = Path(filename).suffix.lower()
            
            # First pass - extension filter
            if ext not in {e.lower() for e in IMAGE_EXTENSIONS}:
                continue
            
            print(f"Checking: {filepath}")
            
            # Second pass - magic byte / size validation
            is_valid, reason = validate_image(filepath)
            
            if is_valid:
                print(f"  VALID: {reason}")
                valid_images.append(filepath)
            else:
                print(f"  SKIPPED: {reason}")
                skipped.append((filepath, reason))
    
    print("-" * 60)
    print(f"\nResults:")
    print(f"  Valid images found: {len(valid_images)}")
    print(f"  Files skipped:      {len(skipped)}")
    
    # Write valid image paths to output file
    if valid_images:
        with open(output_file, 'w') as f:
            for image_path in valid_images:
                f.write(image_path + '\n')
        print(f"\nImage list written to: {output_file}")
    else:
        print("\nNo valid images found. Output file not created.")
    
    # Optionally log skipped files for review
    if skipped:
        skipped_log = output_file.replace('.txt', '_skipped.txt')
        with open(skipped_log, 'w') as f:
            for path, reason in skipped:
                f.write(f"{path} | {reason}\n")
        print(f"Skipped files logged to: {skipped_log}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python find_images.py <search_directory> <output_file>")
        print("Example: python find_images.py E:\\cases\\case047 C:\\tools\\images.txt")
        sys.exit(1)
    
    search_directory = sys.argv[1]
    output_file = sys.argv[2]
    
    find_images(search_directory, output_file)
