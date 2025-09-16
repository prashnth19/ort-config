#!/bin/bash
# swift_scan.sh - Runs Syft scan for Swift projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Swift scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Swift scan completed successfully."
else
    echo "Error occurred during Swift scan."
    exit 1
fi
