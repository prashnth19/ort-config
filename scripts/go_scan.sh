#!/bin/bash
# go_scan.sh - Runs Syft scan for Go projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Go scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Go scan completed successfully."
else
    echo "Error occurred during Go scan."
    exit 1
fi
