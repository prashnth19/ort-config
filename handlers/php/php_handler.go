package phphandler

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
// PHP Handler
// ---------------------------
type PHPHandler struct{}

// Name returns the handler name
func (h *PHPHandler) Name() string {
	return "PHP"
}

// Detect returns true if composer.json, composer.lock, or .php files exist
func (h *PHPHandler) Detect(projectDir string) bool {
	// composer.json
	if _, err := os.Stat(filepath.Join(projectDir, "composer.json")); err == nil {
		return true
	}
	// composer.lock
	if _, err := os.Stat(filepath.Join(projectDir, "composer.lock")); err == nil {
		return true
	}
	// source files
	found := false
	filepath.WalkDir(projectDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".php") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// Scan merges declared deps, lockfile/syft versions, and inferred deps from .php files
func (h *PHPHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// 1. Parse composer.json if exists
	composerPath := filepath.Join(projectDir, "composer.json")
	if _, err := os.Stat(composerPath); err == nil {
		d, err := ParseComposerJSON(composerPath)
		if err != nil {
			return nil, err
		}
		declaredDeps = d
	}

	// 2. Parse composer.lock if exists
	lockPath := filepath.Join(projectDir, "composer.lock")
	var lockDeps []utils.Dependency
	if _, err := os.Stat(lockPath); err == nil {
		data, err := os.ReadFile(lockPath)
		if err == nil {
			lockDeps, _ = ParseComposerLock(data)
		}
	}

	// 3. Parse Syft output if exists
	syftPath := filepath.Join(projectDir, "syft.json")
	var syftDeps []utils.Dependency
	if _, err := os.Stat(syftPath); err == nil {
		data, err := os.ReadFile(syftPath)
		if err == nil {
			syftDeps, _ = utils.ParseSyftJSON(data, "php")
		}
	} else {
		utils.AppendLog("", "[PHPHandler] syft.json not found, versions may be incomplete")
	}

	// 4. Scan .php source files
	codeDeps, err := ParsePHPFiles(projectDir)
	if err != nil {
		return nil, err
	}

	// 5. Merge dependencies
	all := utils.MergeDependencies(declaredDeps, lockDeps)
	all = utils.MergeDependencies(all, syftDeps)
	all = utils.MergeDependencies(all, codeDeps)

	// 6. Apply curations
	finalDeps, err := utils.ApplyCurations(all, "configs/master_curations.yml")
	if err != nil {
		return nil, err
	}

	return finalDeps, nil
}

// GenerateRecoveryFile writes composer.json and creates a timestamped backup
func (h *PHPHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	composerPath := filepath.Join(projectDir, "composer.json")

	// Backup existing
	if _, err := os.Stat(composerPath); err == nil {
		timestamp := time.Now().Format("20060102_150405")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("composer.json.bak.%s", timestamp))
		if err := utils.CopyFile(composerPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup composer.json: %v", err)
		}
		utils.AppendLog("", fmt.Sprintf("[PHPHandler] Backed up composer.json to %s", backupPath))
	}

	if err := WriteComposerJSON(composerPath, deps); err != nil {
		return err
	}
	utils.AppendLog("", "[PHPHandler] Wrote updated composer.json")

	return nil
}

// ---------------------------
// Helper functions
// ---------------------------

type ComposerJSON struct {
	Require    map[string]string `json:"require,omitempty"`
	RequireDev map[string]string `json:"require-dev,omitempty"`
}

func ParseComposerJSON(composerPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(composerPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", composerPath, err)
	}
	var composer ComposerJSON
	if err := json.Unmarshal(data, &composer); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %v", composerPath, err)
	}

	var deps []utils.Dependency
	for name, version := range composer.Require {
		deps = append(deps, utils.Dependency{
			GroupID:    "packagist",
			ArtifactID: name,
			Version:    version,
			Scope:      "compile",
			Key:        name,
		})
	}
	for name, version := range composer.RequireDev {
		deps = append(deps, utils.Dependency{
			GroupID:    "packagist",
			ArtifactID: name,
			Version:    version,
			Scope:      "test",
			Key:        name,
		})
	}
	return deps, nil
}

// ParseComposerLock extracts deps from composer.lock
func ParseComposerLock(data []byte) ([]utils.Dependency, error) {
	type LockFile struct {
		Packages    []map[string]interface{} `json:"packages"`
		PackagesDev []map[string]interface{} `json:"packages-dev"`
	}
	var lock LockFile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("invalid composer.lock: %v", err)
	}
	var deps []utils.Dependency
	for _, pkg := range lock.Packages {
		if name, ok := pkg["name"].(string); ok {
			version := ""
			if v, ok := pkg["version"].(string); ok {
				version = v
			}
			deps = append(deps, utils.Dependency{
				GroupID:    "packagist",
				ArtifactID: name,
				Version:    version,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	for _, pkg := range lock.PackagesDev {
		if name, ok := pkg["name"].(string); ok {
			version := ""
			if v, ok := pkg["version"].(string); ok {
				version = v
			}
			deps = append(deps, utils.Dependency{
				GroupID:    "packagist",
				ArtifactID: name,
				Version:    version,
				Scope:      "test",
				Key:        name,
			})
		}
	}
	return deps, nil
}

// WriteComposerJSON writes curated deps into composer.json
func WriteComposerJSON(composerPath string, deps []utils.Dependency) error {
	composer := ComposerJSON{
		Require:    map[string]string{},
		RequireDev: map[string]string{},
	}
	for _, d := range deps {
		if d.Scope == "test" {
			composer.RequireDev[d.ArtifactID] = d.Version
		} else {
			composer.Require[d.ArtifactID] = d.Version
		}
	}
	data, err := json.MarshalIndent(composer, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal composer.json: %v", err)
	}
	return os.WriteFile(composerPath, data, 0644)
}

// ParsePHPFiles scans .php files for require/include/use statements
func ParsePHPFiles(projectDir string) ([]utils.Dependency, error) {
	var deps []utils.Dependency

	requireRegex := regexp.MustCompile(`\b(require|include)(_once)?\s*['"]([^'"]+)['"]`)
	useRegex := regexp.MustCompile(`^use\s+([A-Za-z0-9_\\]+)`)

	err := filepath.WalkDir(projectDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".php") {
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
			if m := requireRegex.FindStringSubmatch(line); len(m) > 3 {
				pkg := m[3]
				deps = append(deps, utils.Dependency{
					GroupID:    "packagist",
					ArtifactID: pkg,
					Version:    "",
					Scope:      "compile",
					Key:        pkg,
				})
			}
			if m := useRegex.FindStringSubmatch(line); len(m) > 1 {
				pkg := strings.ReplaceAll(m[1], "\\", "/")
				deps = append(deps, utils.Dependency{
					GroupID:    "packagist",
					ArtifactID: pkg,
					Version:    "",
					Scope:      "compile",
					Key:        pkg,
				})
			}
		}
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return deps, nil
}
