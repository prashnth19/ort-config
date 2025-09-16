#!/bin/bash
# dotnet_scan.sh - Runs Syft scan for .NET projects

set -e

PROJECT_DIR=$1
OUTPUT_FILE=$2

echo "Starting .NET scan for $PROJECT_DIR"

syft scan "$PROJECT_DIR" -o json="$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo ".NET scan completed successfully."
else
    echo "Error occurred during .NET scan."
    exit 1
fi
