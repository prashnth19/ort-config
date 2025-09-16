package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RunSyft runs Syft on the given target path (e.g., repo root or a subdir).
// It excludes heavy dirs (node_modules, vendor, .git, venv, __pycache__).
// Results are always written to a JSON file under outputDir, named syft-<lang>.json.
// Returns the full path to the output file.
func RunSyft(target string, lang string, outputDir string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output dir %s: %v", outputDir, err)
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("syft-%s.json", lang))

	// Build syft args
	args := []string{
		target,
		"-o", "json",
		"--exclude", "node_modules",
		"--exclude", "vendor",
		"--exclude", ".git",
		"--exclude", "venv",
		"--exclude", "__pycache__",
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		return "", fmt.Errorf("failed to create syft output file: %v", err)
	}
	defer outFile.Close()

	// Run Syft
	cmd := exec.CommandContext(ctx, "syft", args...)
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("syft failed on target %s for lang %s: %v", target, lang, err)
	}

	return outputFile, nil
}
