#!/usr/bin/env bash
set -euo pipefail

# -----------------------------
# Ensure script is executable
# -----------------------------
SCRIPT_PATH="$(realpath "$0")"
if [ ! -x "$SCRIPT_PATH" ]; then
  echo "[INFO] Fixing permissions for $SCRIPT_PATH"
  chmod +x "$SCRIPT_PATH"
fi

# -----------------------------
# Config
# -----------------------------
REPO_FILE="./configs/repos.json"
BACKUP_DIR="./recovery_files"
SYFT_BIN="syft"
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/recovery_$(date +%Y%m%d_%H%M%S).log"

# -----------------------------
# Check Syft availability
# -----------------------------
if ! command -v "$SYFT_BIN" &>/dev/null; then
  echo "[INFO] Syft not found. Installing..." | tee -a "$LOG_FILE"
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
else
  echo "[INFO] Syft found: $($SYFT_BIN version)" | tee -a "$LOG_FILE"
fi

# -----------------------------
# Install Go dependencies
# -----------------------------
echo "[INFO] Downloading Go dependencies..." | tee -a "$LOG_FILE"
go mod tidy 2>&1 | tee -a "$LOG_FILE"

# -----------------------------
# Remove old syft.json (safety)
# -----------------------------
if [ -f "syft.json" ]; then
  echo "[INFO] Removing old syft.json" | tee -a "$LOG_FILE"
  rm -f syft.json
fi

# -----------------------------
# Build & run Go program
# -----------------------------
echo "[INFO] Building and running ORT Recovery..." | tee -a "$LOG_FILE"
if ! go run main.go \
  -repoFile="$REPO_FILE" \
  -backup="$BACKUP_DIR" \
  -v \
  -keep-temp 2>&1 | tee -a "$LOG_FILE"; then
  echo "[ERROR] ORT Recovery failed. Check $LOG_FILE for details." >&2
  exit 1
fi

# -----------------------------
# Final cleanup
# -----------------------------
if [ -f "syft.json" ]; then
  echo "[INFO] Cleaning up syft.json" | tee -a "$LOG_FILE"
  rm -f syft.json
fi

echo "[INFO] ORT Recovery completed successfully." | tee -a "$LOG_FILE"
echo "[INFO] Logs saved to $LOG_FILE"
