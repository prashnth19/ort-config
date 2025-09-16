#!/bin/bash
# ruby_scan.sh - Runs Syft scan for Ruby projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Ruby scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Ruby scan completed successfully."
else
    echo "Error occurred during Ruby scan."
    exit 1
fi
