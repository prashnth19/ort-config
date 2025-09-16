#!/bin/bash
# php_scan.sh - Runs Syft scan for PHP projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting PHP scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "PHP scan completed successfully."
else
    echo "Error occurred during PHP scan."
    exit 1
fi
