#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 [region|partition|tcache_bin]"
    exit 1
fi

case "$1" in
    "region")
        ./heap_region_inspection.gdb --args heap_experiment 1
        ;;
    "partition")
        ./heap_partition.gdb --args heap_experiment 2
        ;;
    "tcache_bin")
        ./tcache_bin.gdb --args heap_experiment 3
        ;;
    "fast_bin")
        ./fast_bin.gdb --args heap_experiment 4
        ;;
    "unsorted_bin")
        ./unsorted_bin.gdb --args heap_experiment 5
        ;;
    "free_hook")
        ./free_hook.gdb --args heap_experiment 6
        ;;
    *)
        echo "Invalid command: $1"
        exit 1
        ;;
esac

exit 0