#!/bin/bash
# rust_scan.sh - Runs Syft scan for Rust projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Rust scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Rust scan completed successfully."
else
    echo "Error occurred during Rust scan."
    exit 1
fi
