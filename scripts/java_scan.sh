#!/bin/bash
# java_scan.sh - Runs Syft scan for Java projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Java scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Java scan completed successfully."
else
    echo "Error occurred during Java scan."
    exit 1
fi
