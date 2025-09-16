package nodehandler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ort-recovery/utils"
)

// ---------------------------
// Node.js Handler
// ---------------------------
type NodeHandler struct{}

// Name returns the handler name
func (h *NodeHandler) Name() string {
	return "Node.js"
}

// Detect checks if package.json or lockfiles or .js/.ts/.mjs/.cjs files exist
func (h *NodeHandler) Detect(projectDir string) bool {
	// package.json
	if _, err := os.Stat(filepath.Join(projectDir, "package.json")); err == nil {
		return true
	}

	// lockfiles
	lockfiles := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	for _, lf := range lockfiles {
		if _, err := os.Stat(filepath.Join(projectDir, lf)); err == nil {
			return true
		}
	}

	// source files
	found := false
	filepath.WalkDir(projectDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ts") ||
			strings.HasSuffix(path, ".mjs") ||
			strings.HasSuffix(path, ".cjs") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// Scan checks source imports against package.json, fills missing from Syft or leaves as "latest"
func (h *NodeHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// Parse package.json if exists
	pkgPath := filepath.Join(projectDir, "package.json")
	if _, err := os.Stat(pkgPath); err == nil {
		declaredDeps, err = ParsePackageJSON(pkgPath)
		if err != nil {
			return nil, err
		}
	}

	// Collect imports from source
	codeDeps, err := ParseNodeFiles(projectDir)
	if err != nil {
		return nil, err
	}

	// Parse syft.json if exists
	syftPath := filepath.Join(projectDir, "syft.json")
	var syftDeps []utils.Dependency
	if _, err := os.Stat(syftPath); err == nil {
		data, err := os.ReadFile(syftPath)
		if err == nil {
			syftDeps, _ = utils.ParseSyftJSON(data, "node")
		}
	} else {
		utils.AppendLog("", "[NodeHandler] WARNING: syft.json not found, versions may be incomplete")
	}

	// Map declared
	declaredMap := make(map[string]utils.Dependency)
	for _, d := range declaredDeps {
		declaredMap[d.Key] = d
	}

	finalDeps := declaredDeps

	// Add missing ones
	for _, dep := range codeDeps {
		if _, found := declaredMap[dep.Key]; !found {
			version := "latest"
			for _, s := range syftDeps {
				if s.ArtifactID == dep.ArtifactID {
					version = s.Version
					break
				}
			}
			newDep := utils.Dependency{
				GroupID:    "npm",
				ArtifactID: dep.ArtifactID,
				Version:    version,
				Scope:      "compile",
				Key:        dep.Key,
			}
			finalDeps = append(finalDeps, newDep)

			if version == "latest" {
				utils.AppendLog("", fmt.Sprintf("[NodeHandler] Added missing dependency: %s (version unknown, using 'latest')", dep.Key))
			} else {
				utils.AppendLog("", fmt.Sprintf("[NodeHandler] Added missing dependency: %s %s (from Syft)", dep.Key, version))
			}
		}
	}

	return finalDeps, nil
}

// GenerateRecoveryFile writes package.json (or creates new one) and backs up old version safely
func (h *NodeHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	pkgPath := filepath.Join(projectDir, "package.json")

	// Backup if exists
	if _, err := os.Stat(pkgPath); err == nil {
		timestamp := time.Now().Format("20060102_150405")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("package.json.bak.%s", timestamp))
		if err := utils.CopyFile(pkgPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup package.json: %v", err)
		}
		utils.AppendLog("", fmt.Sprintf("[NodeHandler] Backed up existing package.json to %s", backupPath))
	}

	// Write new one
	if err := WritePackageJSON(pkgPath, deps); err != nil {
		return err
	}
	utils.AppendLog("", "[NodeHandler] Wrote updated package.json")

	return nil
}

// ---------------------------
// Helpers
// ---------------------------

type PackageJSON struct {
	Dependencies    map[string]string `json:"dependencies,omitempty"`
	DevDependencies map[string]string `json:"devDependencies,omitempty"`
}

// ParsePackageJSON → []Dependency
func ParsePackageJSON(pkgPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %v", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("invalid package.json: %v", err)
	}

	var deps []utils.Dependency
	for name, version := range pkg.Dependencies {
		deps = append(deps, utils.Dependency{
			GroupID:    "npm",
			ArtifactID: name,
			Version:    version,
			Scope:      "compile",
			Key:        name,
		})
	}
	for name, version := range pkg.DevDependencies {
		deps = append(deps, utils.Dependency{
			GroupID:    "npm",
			ArtifactID: name,
			Version:    version,
			Scope:      "test",
			Key:        name,
		})
	}
	return deps, nil
}

// WritePackageJSON writes curated deps into package.json
func WritePackageJSON(pkgPath string, deps []utils.Dependency) error {
	pkg := PackageJSON{
		Dependencies:    map[string]string{},
		DevDependencies: map[string]string{},
	}
	for _, d := range deps {
		if d.Scope == "test" {
			pkg.DevDependencies[d.ArtifactID] = d.Version
		} else {
			pkg.Dependencies[d.ArtifactID] = d.Version
		}
	}
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal package.json: %v", err)
	}
	return os.WriteFile(pkgPath, data, 0644)
}

// ParseNodeFiles → recursively find require/import deps in .js/.ts/.mjs/.cjs
func ParseNodeFiles(projectDir string) ([]utils.Dependency, error) {
	var deps []utils.Dependency

	importRegex := regexp.MustCompile(`^(?:import|const|let|var).*['"]([^'"]+)['"]`)
	requireRegex := regexp.MustCompile(`require\(['"]([^'"]+)['"]\)`)

	err := filepath.WalkDir(projectDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !(strings.HasSuffix(path, ".js") ||
			strings.HasSuffix(path, ".ts") ||
			strings.HasSuffix(path, ".mjs") ||
			strings.HasSuffix(path, ".cjs")) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if m := importRegex.FindStringSubmatch(line); len(m) > 1 {
				pkg := m[1]
				if !strings.HasPrefix(pkg, ".") {
					deps = append(deps, utils.Dependency{
						GroupID:    "npm",
						ArtifactID: pkg,
						Version:    "",
						Scope:      "compile",
						Key:        pkg,
					})
				}
			}
			if m := requireRegex.FindStringSubmatch(line); len(m) > 1 {
				pkg := m[1]
				if !strings.HasPrefix(pkg, ".") {
					deps = append(deps, utils.Dependency{
						GroupID:    "npm",
						ArtifactID: pkg,
						Version:    "",
						Scope:      "compile",
						Key:        pkg,
					})
				}
			}
		}
		return scanner.Err()
	})

	if err != nil {
		return nil, err
	}
	return deps, nil
}
