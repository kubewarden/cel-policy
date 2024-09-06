#!/usr/bin/env bash

set -eux

: ${REPOSITORY_DIR?"Missing REPOSITORY_DIR environment variable. This is the base directory where the files to be copied are located"}
: ${DESTINATION_DIR?"Missing DESTINATION_DIR environment variable. This is the directory where the files will be copied into"}
: ${FILES?"Missing FILES environment variable. These are the files to be copied, separated by spaces. Example: FILES=\"file1 file2 file3\""}

# Check if the repository directory exists
if [ ! -d "$REPOSITORY_DIR" ]; then
    echo "Error: Base directory $REPOSITORY_DIR does not exist."
    exit 1
fi

# Check if the destination directory exists
if [ ! -d "$DESTINATION_DIR" ]; then
    echo "Error: Destination directory $DESTINNATION_DIR does not exist."
    exit 1
fi


# Loop through each file in the list
for file in $FILES; do
    # Find the file in the base directory
    file_path="$REPOSITORY_DIR/$file"
    
    if [ -n "$file_path" ]; then
        # Use the install command to copy the file and create the necessary directories
        install -m "644" -D "$file_path" "$DESTINATION_DIR/$file"
        echo "Copied $file_path to $DESTINATION_DIR/$file"
    else
        echo "File '$file_path' not found in $REPOSITORY_DIR."
	exit 1
    fi
done

echo "Done!"
