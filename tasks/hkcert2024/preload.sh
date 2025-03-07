#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: $0 <bin> <ld> <libc_directory>"
    echo
    echo "Arguments:"
    echo "  bin              Path to the binary file."
    echo "  ld               Path to the linker."
    echo "  libc_directory   Path to the libc directory."
    echo
    echo "Example:"
    echo "  $0 /path/to/bin /path/to/ld /path/to/libc"
    exit 1
}

# Check if the number of arguments is not equal to 3
if [ "$#" -ne 3 ]; then
    usage
fi

# Assign arguments to variables
bin="$1"
ld="$2"
libc_directory="$3"

patchelf --set-interpreter $ld $bin
patchelf --set-rpath $libc_directory $bin
