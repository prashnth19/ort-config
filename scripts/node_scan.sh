#!/bin/bash
# node_scan.sh - Runs Syft scan for Node.js projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting Node.js scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo "Node.js scan completed successfully."
else
    echo "Error occurred during Node.js scan."
    exit 1
fi
