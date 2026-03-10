#!/bin/bash

METADATA_FILE="/path/to/full_metadata.txt"
SOURCE="/mnt/vmfs"
DEST="/mnt/ext4_out"

echo "Starting timestamp restoration..."

while IFS='|' read -r name inode perms uid gid size atime mtime ctime btime; do
    newpath="${name/$SOURCE/$DEST}"
    if [ -e "$newpath" ]; then
        sudo touch -a -d "@$atime" "$newpath"
        sudo touch -m -d "@$mtime" "$newpath"
        echo "Restored: $newpath"
    else
        echo "MISSING: $newpath"
    fi
done < "$METADATA_FILE"

echo "Done!"
