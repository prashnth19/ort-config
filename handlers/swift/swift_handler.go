package swifthandler

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
// Swift Handler
// ---------------------------
type SwiftHandler struct{}

// Name returns the handler name
func (h *SwiftHandler) Name() string {
	return "Swift"
}

// Detect returns true if Swift dependency files exist
func (h *SwiftHandler) Detect(projectDir string) bool {
	files := []string{"Package.swift", "Package.resolved", "*.podspec", "Cartfile"}
	for _, f := range files {
		matches, _ := filepath.Glob(filepath.Join(projectDir, f))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

// Scan parses Swift dependency files + Syft + source
func (h *SwiftHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// Parse Package.swift
	if _, err := os.Stat(filepath.Join(projectDir, "Package.swift")); err == nil {
		d, _ := ParsePackageSwift(filepath.Join(projectDir, "Package.swift"))
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[SwiftHandler] Parsed Package.swift, found %d dependencies", len(d))
	}

	// Parse Package.resolved
	if _, err := os.Stat(filepath.Join(projectDir, "Package.resolved")); err == nil {
		d, _ := ParsePackageResolved(filepath.Join(projectDir, "Package.resolved"))
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[SwiftHandler] Parsed Package.resolved, found %d dependencies", len(d))
	}

	// Parse .podspec
	files, _ := filepath.Glob(filepath.Join(projectDir, "*.podspec"))
	for _, f := range files {
		d, _ := ParsePodspec(f)
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[SwiftHandler] Parsed %s, found %d dependencies", filepath.Base(f), len(d))
	}

	// Parse Cartfile
	if _, err := os.Stat(filepath.Join(projectDir, "Cartfile")); err == nil {
		d, _ := ParseCartfile(filepath.Join(projectDir, "Cartfile"))
		declaredDeps = append(declaredDeps, d...)
		utils.AppendLog(projectDir, "[SwiftHandler] Parsed Cartfile, found %d dependencies", len(d))
	}

	// Parse Syft
	syftData, err := os.ReadFile(filepath.Join(projectDir, "syft.json"))
	if err != nil {
		utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to read syft.json: %v", err)
		return nil, fmt.Errorf("failed to read syft.json: %v", err)
	}
	syftDeps, err := utils.ParseSyftJSON(syftData, "swift")
	if err != nil {
		utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to parse syft.json: %v", err)
		return nil, err
	}
	utils.AppendLog(projectDir, "[SwiftHandler] Parsed syft.json, found %d dependencies", len(syftDeps))

	// Scan .swift files
	usedDeps, err := ScanSwiftFiles(projectDir)
	if err != nil {
		utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to scan Swift files: %v", err)
		return nil, err
	}
	utils.AppendLog(projectDir, "[SwiftHandler] Scanned .swift files, found %d dependencies", len(usedDeps))

	// Reconcile declared + used + syft
	combined := append(append(declaredDeps, usedDeps...), syftDeps...)
	finalDeps, err := utils.ReconcileDependencies(combined)
	if err != nil {
		utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to reconcile dependencies: %v", err)
		return nil, err
	}

	return finalDeps, nil
}

// GenerateRecoveryFile writes Package.swift and backup
func (h *SwiftHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	packagePath := filepath.Join(projectDir, "Package.swift")

	// Backup Package.swift
	if _, err := os.Stat(packagePath); err == nil {
		backupPath := filepath.Join(backupDir, "Package_backup.swift")
		if err := utils.CopyFile(packagePath, backupPath); err != nil {
			utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to backup Package.swift: %v", err)
			return fmt.Errorf("failed to backup Package.swift: %v", err)
		}
		utils.AppendLog(projectDir, "[SwiftHandler] Backed up Package.swift to %s", backupPath)
	}

	err := WritePackageSwift(packagePath, deps)
	if err != nil {
		utils.AppendLog(projectDir, "[SwiftHandler] ERROR: failed to write Package.swift: %v", err)
		return err
	}
	utils.AppendLog(projectDir, "[SwiftHandler] Generated new Package.swift with %d dependencies", len(deps))
	return nil
}

// ---------------------------
// Helpers
// ---------------------------

// ParsePackageSwift
func ParsePackageSwift(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var deps []utils.Dependency
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`\.package\s*\(\s*url:\s*\"([^\"]+)\".*from:\s*\"([^\"]+)\"`)
	for scanner.Scan() {
		line := scanner.Text()
		if m := re.FindStringSubmatch(line); len(m) == 3 {
			url, version := m[1], m[2]
			name := filepath.Base(strings.TrimSuffix(url, ".git"))
			deps = append(deps, utils.Dependency{
				GroupID:    "swiftpm",
				ArtifactID: name,
				Version:    version,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	return deps, scanner.Err()
}

// ParsePackageResolved (JSON-like lockfile)
func ParsePackageResolved(path string) ([]utils.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	var deps []utils.Dependency
	re := regexp.MustCompile(`"identity"\s*:\s*"([^"]+)".*?"version"\s*:\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		deps = append(deps, utils.Dependency{
			GroupID:    "swiftpm",
			ArtifactID: m[1],
			Version:    m[2],
			Scope:      "compile",
			Key:        m[1],
		})
	}
	return deps, nil
}

// ParsePodspec
func ParsePodspec(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var deps []utils.Dependency
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`s\.dependency\s+['"]([^'"]+)['"]\s*,?\s*['"]?([^'"]*)['"]?`)
	for scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); len(m) >= 2 {
			deps = append(deps, utils.Dependency{
				GroupID:    "cocoapods",
				ArtifactID: m[1],
				Version:    strings.TrimSpace(m[2]),
				Scope:      "compile",
				Key:        m[1],
			})
		}
	}
	return deps, scanner.Err()
}

// ParseCartfile
func ParseCartfile(path string) ([]utils.Dependency, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var deps []utils.Dependency
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`github\s+"([^/]+)/([^"]+)"\s+~>\s+([0-9.]+)`)
	for scanner.Scan() {
		if m := re.FindStringSubmatch(scanner.Text()); len(m) == 4 {
			name := m[2]
			deps = append(deps, utils.Dependency{
				GroupID:    "carthage",
				ArtifactID: name,
				Version:    m[3],
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	return deps, scanner.Err()
}

// ScanSwiftFiles extracts "import Foo"
func ScanSwiftFiles(projectDir string) ([]utils.Dependency, error) {
	var deps []utils.Dependency
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".swift") {
			return nil
		}
		data, _ := os.ReadFile(path)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "import ") {
				name := strings.TrimPrefix(line, "import ")
				deps = append(deps, utils.Dependency{
					GroupID:    "swift",
					ArtifactID: name,
					Version:    "",
					Scope:      "compile",
					Key:        name,
				})
			}
		}
		return nil
	})
	return deps, err
}

// WritePackageSwift regenerates Package.swift
func WritePackageSwift(path string, deps []utils.Dependency) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	header := `// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "RecoveredApp",
    dependencies: [
`
	if _, err := writer.WriteString(header); err != nil {
		return err
	}

	for _, d := range deps {
		version := d.Version
		if version == "" {
			version = "*"
		}
		line := fmt.Sprintf(`        .package(url: "https://github.com/%s/%s.git", from: "%s"),`+"\n",
			"org", d.ArtifactID, version)
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}

	footer := `    ]
)`
	if _, err := writer.WriteString(footer); err != nil {
		return err
	}

	return writer.Flush()
}
