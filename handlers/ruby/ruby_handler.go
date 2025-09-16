package rubyhandler

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
// Ruby Handler
// ---------------------------
type RubyHandler struct{}

// Name returns the handler name
func (h *RubyHandler) Name() string {
	return "Ruby"
}

// Detect: true if Gemfile, Gemfile.lock, or .gemspec exists
func (h *RubyHandler) Detect(projectDir string) bool {
	files := []string{"Gemfile", "Gemfile.lock"}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(projectDir, f)); err == nil {
			utils.AppendLog(projectDir, fmt.Sprintf("Detected %s in project", f))
			return true
		}
	}
	// check .gemspec
	matches, _ := filepath.Glob(filepath.Join(projectDir, "*.gemspec"))
	if len(matches) > 0 {
		utils.AppendLog(projectDir, "Detected .gemspec in project")
		return true
	}
	return false
}

// Scan parses declared files + Syft, compares with .rb requires
func (h *RubyHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// Parse Gemfile
	if _, err := os.Stat(filepath.Join(projectDir, "Gemfile")); err == nil {
		utils.AppendLog(projectDir, "Parsing Gemfile...")
		d, _ := ParseGemfile(filepath.Join(projectDir, "Gemfile"))
		declaredDeps = append(declaredDeps, d...)
	}

	// Parse Gemfile.lock
	if _, err := os.Stat(filepath.Join(projectDir, "Gemfile.lock")); err == nil {
		utils.AppendLog(projectDir, "Parsing Gemfile.lock...")
		d, _ := ParseGemfileLock(filepath.Join(projectDir, "Gemfile.lock"))
		declaredDeps = append(declaredDeps, d...)
	}

	// Parse .gemspec
	matches, _ := filepath.Glob(filepath.Join(projectDir, "*.gemspec"))
	for _, gemspec := range matches {
		utils.AppendLog(projectDir, fmt.Sprintf("Parsing gemspec: %s", gemspec))
		d, _ := ParseGemspec(gemspec)
		declaredDeps = append(declaredDeps, d...)
	}

	// Parse Syft output
	syftData, err := os.ReadFile(filepath.Join(projectDir, "syft.json"))
	if err != nil {
		utils.AppendLog(projectDir, "Failed to read syft.json")
		return nil, fmt.Errorf("failed to read syft.json: %v", err)
	}
	syftDeps, err := utils.ParseSyftJSON(syftData, "ruby")
	if err != nil {
		utils.AppendLog(projectDir, "Failed to parse syft.json")
		return nil, err
	}

	// Scan .rb files for `require`
	usedDeps, err := ScanRubyFiles(projectDir)
	if err != nil {
		utils.AppendLog(projectDir, "Failed to scan Ruby files")
		return nil, err
	}

	// Merge all sources before reconciliation
	allDeps := append(declaredDeps, usedDeps...)
	allDeps = append(allDeps, syftDeps...)

	// Reconcile with new function signature
	finalDeps, err := utils.ReconcileDependencies(allDeps)
	if err != nil {
		return nil, err
	}

	utils.AppendLog(projectDir, fmt.Sprintf("Scan complete: %d dependencies found", len(finalDeps)))
	return finalDeps, nil
}

// GenerateRecoveryFile updates Gemfile (main declaration) and backup
func (h *RubyHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	gemfilePath := filepath.Join(projectDir, "Gemfile")

	// Backup if exists
	if _, err := os.Stat(gemfilePath); err == nil {
		backupPath := filepath.Join(backupDir, "Gemfile_backup")
		if err := utils.CopyFile(gemfilePath, backupPath); err != nil {
			utils.AppendLog(projectDir, "Failed to backup Gemfile")
			return fmt.Errorf("failed to backup Gemfile: %v", err)
		}
		utils.AppendLog(projectDir, "Gemfile backup created")
	}

	utils.AppendLog(projectDir, "Writing recovery Gemfile...")
	return WriteGemfile(gemfilePath, deps)
}

// ---------------------------
// Helpers
// ---------------------------

// ParseGemfile extracts gem declarations
func ParseGemfile(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		utils.AppendLog("", fmt.Sprintf("Failed to open Gemfile: %v", err))
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	re := regexp.MustCompile(`gem ["']([^"']+)["'](,\s*["']([^"']+)["'])?`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := re.FindStringSubmatch(line); m != nil {
			deps = append(deps, utils.Dependency{
				GroupID:    "rubygems",
				ArtifactID: m[1],
				Version:    m[3],
				Scope:      "compile",
				Key:        m[1],
			})
		}
	}
	return deps, scanner.Err()
}

// ParseGemfileLock parses Gemfile.lock specs
func ParseGemfileLock(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		utils.AppendLog("", fmt.Sprintf("Failed to open Gemfile.lock: %v", err))
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	inSpecs := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs {
			if strings.Contains(line, " ") {
				parts := strings.Split(line, " ")
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(parts[1], "() ")
				deps = append(deps, utils.Dependency{
					GroupID:    "rubygems",
					ArtifactID: name,
					Version:    version,
					Scope:      "compile",
					Key:        name,
				})
			}
		}
	}
	return deps, scanner.Err()
}

// ParseGemspec parses .gemspec dependencies
func ParseGemspec(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		utils.AppendLog("", fmt.Sprintf("Failed to open gemspec: %v", err))
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	re := regexp.MustCompile(`add_dependency ["']([^"']+)["'](,\s*["']([^"']+)["'])?`)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if m := re.FindStringSubmatch(line); m != nil {
			deps = append(deps, utils.Dependency{
				GroupID:    "rubygems",
				ArtifactID: m[1],
				Version:    m[3],
				Scope:      "compile",
				Key:        m[1],
			})
		}
	}
	return deps, scanner.Err()
}

// ScanRubyFiles finds `require "x"`
func ScanRubyFiles(projectDir string) ([]utils.Dependency, error) {
	var deps []utils.Dependency
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".rb") {
			return nil
		}
		data, _ := os.ReadFile(path)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "require") {
				parts := strings.Fields(line)
				if len(parts) > 1 {
					name := strings.Trim(parts[1], `"'`)
					deps = append(deps, utils.Dependency{
						GroupID:    "rubygems",
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
	if err != nil {
		utils.AppendLog(projectDir, "Error scanning Ruby files")
	}
	return deps, err
}

// WriteGemfile regenerates Gemfile
func WriteGemfile(path string, deps []utils.Dependency) error {
	file, err := os.Create(path)
	if err != nil {
		utils.AppendLog("", fmt.Sprintf("Failed to create Gemfile: %v", err))
		return err
	}
	defer file.Close()

	for _, d := range deps {
		version := d.Version
		if version == "" {
			// leave empty, ORT will treat as unknown
			_, err = file.WriteString(fmt.Sprintf("gem \"%s\"\n", d.ArtifactID))
		} else {
			_, err = file.WriteString(fmt.Sprintf("gem \"%s\", \"%s\"\n", d.ArtifactID, version))
		}
		if err != nil {
			utils.AppendLog("", fmt.Sprintf("Failed to write Gemfile entry for %s", d.ArtifactID))
			return err
		}
	}
	utils.AppendLog("", "Gemfile written successfully")
	return nil
}
