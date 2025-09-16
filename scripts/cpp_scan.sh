#!/bin/bash
# cpp_scan.sh - Runs Syft scan for C++ projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting C++ scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "C++ scan completed successfully."
else
    echo "Error occurred during C++ scan."
    exit 1
fi
