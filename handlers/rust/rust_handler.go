package rusthandler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ort-recovery/utils"
)

// ---------------------------
// Rust Handler
// ---------------------------
type RustHandler struct{}

// Name returns the handler name
func (h *RustHandler) Name() string {
	return "Rust"
}

// Detect returns true if Cargo.toml or Cargo.lock exists
func (h *RustHandler) Detect(projectDir string) bool {
	files := []string{"Cargo.toml", "Cargo.lock"}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(projectDir, f)); err == nil {
			return true
		}
	}
	return false
}

// Scan parses Cargo.toml, Cargo.lock, Syft, and .rs files
func (h *RustHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// Parse Cargo.toml
	if _, err := os.Stat(filepath.Join(projectDir, "Cargo.toml")); err == nil {
		d, _ := ParseCargoToml(filepath.Join(projectDir, "Cargo.toml"))
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[RustHandler] Parsed Cargo.toml, found %d dependencies", len(d))
	}

	// Parse Cargo.lock
	if _, err := os.Stat(filepath.Join(projectDir, "Cargo.lock")); err == nil {
		d, _ := ParseCargoLock(filepath.Join(projectDir, "Cargo.lock"))
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[RustHandler] Parsed Cargo.lock, found %d dependencies", len(d))
	}

	// Parse Syft
	syftData, err := os.ReadFile(filepath.Join(projectDir, "syft.json"))
	if err != nil {
		utils.AppendLog(projectDir, "[RustHandler] ERROR: failed to read syft.json: %v", err)
		return nil, fmt.Errorf("failed to read syft.json: %v", err)
	}
	syftDeps, err := utils.ParseSyftJSON(syftData, "rust")
	if err != nil {
		utils.AppendLog(projectDir, "[RustHandler] ERROR: failed to parse syft.json: %v", err)
		return nil, err
	}
	utils.AppendLog(projectDir, "[RustHandler] Parsed syft.json, found %d dependencies", len(syftDeps))

	// Scan .rs files
	usedDeps, err := ScanRustFiles(projectDir)
	if err != nil {
		utils.AppendLog(projectDir, "[RustHandler] ERROR: failed to scan Rust files: %v", err)
		return nil, err
	}
	utils.AppendLog(projectDir, "[RustHandler] Scanned .rs files, found %d dependencies", len(usedDeps))

	// Merge all sources before reconciliation
	allDeps := append(declaredDeps, usedDeps...)
	allDeps = append(allDeps, syftDeps...)

	// Reconcile with new function signature
	finalDeps, err := utils.ReconcileDependencies(allDeps)
	if err != nil {
		return nil, err
	}

	utils.AppendLog(projectDir, "[RustHandler] Reconciled dependencies, final count: %d", len(finalDeps))
	return finalDeps, nil
}

// GenerateRecoveryFile updates Cargo.toml and backup
func (h *RustHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	cargoPath := filepath.Join(projectDir, "Cargo.toml")

	// Backup if exists
	if _, err := os.Stat(cargoPath); err == nil {
		backupPath := filepath.Join(backupDir, "Cargo_backup.toml")
		if err := utils.CopyFile(cargoPath, backupPath); err != nil {
			utils.AppendLog(projectDir, "[RustHandler] ERROR: failed to backup Cargo.toml: %v", err)
			return fmt.Errorf("failed to backup Cargo.toml: %v", err)
		}
		utils.AppendLog(projectDir, "[RustHandler] Backed up Cargo.toml to %s", backupPath)
	}

	err := WriteCargoToml(cargoPath, deps)
	if err != nil {
		utils.AppendLog(projectDir, "[RustHandler] ERROR: failed to write Cargo.toml: %v", err)
		return err
	}
	utils.AppendLog(projectDir, "[RustHandler] Generated new Cargo.toml with %d dependencies", len(deps))
	return nil
}

// ---------------------------
// Helpers
// ---------------------------

// ParseCargoToml reads Cargo.toml
func ParseCargoToml(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	section := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[dependencies]") {
			section = "compile"
			continue
		} else if strings.HasPrefix(line, "[dev-dependencies]") {
			section = "test"
			continue
		} else if strings.HasPrefix(line, "[build-dependencies]") {
			section = "build"
			continue
		} else if strings.HasPrefix(line, "[") {
			section = ""
		}

		if section != "" && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				deps = append(deps, utils.Dependency{
					GroupID:    "crates",
					ArtifactID: name,
					Version:    version,
					Scope:      section,
					Key:        name,
				})
			}
		}
	}

	return deps, scanner.Err()
}

// ParseCargoLock reads Cargo.lock for resolved versions
func ParseCargoLock(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	inPkg := false
	var name, version string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if name != "" {
				deps = append(deps, utils.Dependency{
					GroupID:    "crates",
					ArtifactID: name,
					Version:    version,
					Scope:      "compile",
					Key:        name,
				})
			}
			inPkg = true
			name, version = "", ""
			continue
		}

		if inPkg {
			if strings.HasPrefix(line, "name =") {
				name = strings.Trim(strings.Split(line, "=")[1], ` "`)
			}
			if strings.HasPrefix(line, "version =") {
				version = strings.Trim(strings.Split(line, "=")[1], ` "`)
			}
		}
	}

	// Append last package
	if name != "" {
		deps = append(deps, utils.Dependency{
			GroupID:    "crates",
			ArtifactID: name,
			Version:    version,
			Scope:      "compile",
			Key:        name,
		})
	}

	return deps, scanner.Err()
}

// ScanRustFiles extracts extern crate / use statements
func ScanRustFiles(projectDir string) ([]utils.Dependency, error) {
	var deps []utils.Dependency
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".rs") {
			return nil
		}
		data, _ := os.ReadFile(path)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "extern crate ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					name := strings.Trim(parts[2], ";")
					deps = append(deps, utils.Dependency{
						GroupID:    "crates",
						ArtifactID: name,
						Version:    "",
						Scope:      "compile",
						Key:        name,
					})
				}
			}
			if strings.HasPrefix(line, "use ") {
				re := regexp.MustCompile(`use\s+([a-zA-Z0-9_]+)::`)
				if m := re.FindStringSubmatch(line); m != nil {
					name := m[1]
					deps = append(deps, utils.Dependency{
						GroupID:    "crates",
						ArtifactID: name,
						Version:    "",
						Scope:      "compile",
						Key:        name,
					})
				}
			}
		}
		return nil
	})
	return deps, err
}

// WriteCargoToml regenerates Cargo.toml
func WriteCargoToml(path string, deps []utils.Dependency) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString("[package]\nname = \"generated\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n")
	if err != nil {
		return err
	}

	_, err = file.WriteString("[dependencies]\n")
	if err != nil {
		return err
	}

	for _, d := range deps {
		if d.Scope == "compile" {
			if d.Version == "" {
				_, err = file.WriteString(fmt.Sprintf("%s = \"*\"\n", d.ArtifactID))
			} else {
				_, err = file.WriteString(fmt.Sprintf("%s = \"%s\"\n", d.ArtifactID, d.Version))
			}
			if err != nil {
				return err
			}
		}
	}

	return nil
}
