#!/bin/bash
# python_scan.sh - Runs Syft scan for Python projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Python scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Python scan completed successfully."
else
    echo "Error occurred during Python scan."
    exit 1
fi
