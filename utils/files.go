package utils

import (
	"fmt"
	"io"
	"os"
)

// CopyFile copies a file from src to dst, creating or truncating dst.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %v", src, err)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %v", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("failed to copy from %s to %s: %v", src, dst, err)
	}

	return out.Close()
}
