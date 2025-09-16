package cpp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ort-recovery/utils"
)

// ---------------------------
// C++ Handler (extended)
// ---------------------------
type CppHandler struct{}

func (h *CppHandler) Name() string {
	return "C++"
}

// Detect returns true if any known C/C++ manifest exists
func (h *CppHandler) Detect(projectDir string) bool {
	candidates := []string{
		"vcpkg.json",
		"conanfile.txt",
		"conanfile.py",
		"CMakeLists.txt",
		"Makefile",
		"meson.build",
		"BUILD", // Bazel
		"configure.ac",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(projectDir, c)); err == nil {
			return true
		}
	}
	// also detect C/C++ source files
	foundSource := false
	_ = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".c" || ext == ".cpp" || ext == ".cc" || ext == ".cxx" || ext == ".h" || ext == ".hpp" {
				foundSource = true
				return filepath.SkipDir
			}
		}
		return nil
	})
	return foundSource
}

// Scan parses declared deps from many manifests, scans includes, uses Syft, fills missing
func (h *CppHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	// 1. Parse all known manifests (each parser returns empty list if file missing)
	vcpkgDeps, err := ParseVcpkgJSON(filepath.Join(projectDir, "vcpkg.json"))
	if err != nil {
		return nil, err
	}
	conanTxtDeps, err := ParseConanFile(filepath.Join(projectDir, "conanfile.txt"))
	if err != nil {
		return nil, err
	}
	conanPyDeps, err := ParseConanPy(filepath.Join(projectDir, "conanfile.py"))
	if err != nil {
		return nil, err
	}
	cmakeDeps, err := ParseCMakeLists(filepath.Join(projectDir, "CMakeLists.txt"))
	if err != nil {
		return nil, err
	}
	makeDeps, err := ParseMakefile(filepath.Join(projectDir, "Makefile"))
	if err != nil {
		return nil, err
	}
	mesonDeps, err := ParseMesonBuild(filepath.Join(projectDir, "meson.build"))
	if err != nil {
		return nil, err
	}
	bazelDeps, err := ParseBazelBUILD(filepath.Join(projectDir, "BUILD"))
	if err != nil {
		return nil, err
	}
	configureDeps, err := ParseConfigureAC(filepath.Join(projectDir, "configure.ac"))
	if err != nil {
		return nil, err
	}

	// Merge declared deps
	declaredDeps := make([]utils.Dependency, 0)
	declaredDeps = append(declaredDeps, vcpkgDeps...)
	declaredDeps = append(declaredDeps, conanTxtDeps...)
	declaredDeps = append(declaredDeps, conanPyDeps...)
	declaredDeps = append(declaredDeps, cmakeDeps...)
	declaredDeps = append(declaredDeps, makeDeps...)
	declaredDeps = append(declaredDeps, mesonDeps...)
	declaredDeps = append(declaredDeps, bazelDeps...)
	declaredDeps = append(declaredDeps, configureDeps...)

	declaredMap := make(map[string]utils.Dependency)
	for _, d := range declaredDeps {
		declaredMap[d.ArtifactID] = d
	}

	// 2. Scan source files for includes (wider extension coverage)
	includes, err := CollectCppIncludes(projectDir)
	if err != nil {
		return nil, err
	}

	// 3. Parse Syft output
	syftPath := filepath.Join(projectDir, "syft.json")
	syftMap := make(map[string]string)
	if data, err := os.ReadFile(syftPath); err == nil {
		if syftDeps, err := utils.ParseSyftJSON(data, "cpp"); err == nil {
			for _, d := range syftDeps {
				syftMap[d.ArtifactID] = d.Version
			}
		} else {
			// non-fatal; log and continue
			_ = utils.AppendLog(projectDir, "[CppHandler] Warning: failed to parse syft.json: %v", err)
		}
	} else {
		_ = utils.AppendLog(projectDir, "[CppHandler] No syft.json present at %s (will fallback to unknown/latest where needed)", syftPath)
	}

	// 4. Build final list
	final := make([]utils.Dependency, 0)
	seen := make(map[string]struct{})

	// Keep declared as-is
	for _, d := range declaredDeps {
		// avoid duplicates
		if _, ok := seen[d.ArtifactID]; ok {
			continue
		}
		final = append(final, d)
		seen[d.ArtifactID] = struct{}{}
	}

	// Add missing includes
	for _, inc := range includes {
		// Normalize include to artifact id (basic heuristic: take package part before any header path)
		artifact := NormalizeIncludeToArtifact(inc)
		if artifact == "" {
			continue
		}
		if _, ok := seen[artifact]; ok {
			continue
		}
		version := ""
		if v, ok := syftMap[artifact]; ok && v != "" {
			version = v
		} else {
			// follow workflow: leave version empty so ORT marks as unknown (avoid "latest" unless necessary)
			version = ""
		}
		dep := utils.Dependency{
			GroupID:    "cpp",
			ArtifactID: artifact,
			Version:    version,
			Scope:      "compile",
			Key:        artifact,
		}
		final = append(final, dep)
		seen[artifact] = struct{}{}

		if version == "" {
			_ = utils.AppendLog(projectDir, "[CppHandler] Added missing dependency: %s (version unknown — will be marked unknown by ORT)", artifact)
		} else {
			_ = utils.AppendLog(projectDir, "[CppHandler] Added missing dependency: %s %s (from Syft)", artifact, version)
		}
	}

	// If no manifest files but includes exist → new vcpkg.json (fallback)
	if len(declaredDeps) == 0 && len(includes) > 0 {
		_ = utils.AppendLog(projectDir, "[CppHandler] No C++ manifests found; will create fallback vcpkg.json with %d dependencies.", len(includes))
	}

	return final, nil
}

// GenerateRecoveryFile writes updated recovery manifests (backups included)
// Preference order:
// - If Conan (txt or py) originally present -> write conanfile.txt (requires)
// - Else -> write vcpkg.json as fallback
// If other build systems exist (CMake, Bazel, Meson, Makefile, Autotools) we also log and write fallback vcpkg.json, but leave manual guidance.
func (h *CppHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	// check for presence of original manifests
	hasConanTxt := fileExists(filepath.Join(projectDir, "conanfile.txt"))
	hasConanPy := fileExists(filepath.Join(projectDir, "conanfile.py"))
	hasVcpkg := fileExists(filepath.Join(projectDir, "vcpkg.json"))
	hasCMake := fileExists(filepath.Join(projectDir, "CMakeLists.txt"))
	hasBazel := fileExists(filepath.Join(projectDir, "BUILD"))
	hasMeson := fileExists(filepath.Join(projectDir, "meson.build"))
	hasMake := fileExists(filepath.Join(projectDir, "Makefile"))
	hasConfigure := fileExists(filepath.Join(projectDir, "configure.ac"))

	// If conan present prefer conan
	if hasConanTxt || hasConanPy {
		// backup existing conanfile.txt if exists
		conanPath := filepath.Join(projectDir, "conanfile.txt")
		if hasConanTxt {
			backupPath := filepath.Join(backupDir, "conanfile_backup.txt")
			if err := utils.CopyFile(conanPath, backupPath); err != nil {
				return fmt.Errorf("failed to backup conanfile.txt: %v", err)
			}
			_ = utils.AppendLog(projectDir, "[CppHandler] Backed up existing conanfile.txt")
		} else if hasConanPy {
			// if only conanfile.py exists, back it up and still write conanfile.txt (text form) as recovery
			backupPath := filepath.Join(backupDir, "conanfile_py_backup.py")
			if err := utils.CopyFile(filepath.Join(projectDir, "conanfile.py"), backupPath); err != nil {
				return fmt.Errorf("failed to backup conanfile.py: %v", err)
			}
			_ = utils.AppendLog(projectDir, "[CppHandler] Backed up existing conanfile.py")
		}

		if err := WriteConanFile(filepath.Join(projectDir, "conanfile.txt"), deps); err != nil {
			return err
		}
		_ = utils.AppendLog(projectDir, "[CppHandler] Wrote updated conanfile.txt (recovery)")
		return nil
	}

	// else write vcpkg.json (backup if exists)
	vcpkgPath := filepath.Join(projectDir, "vcpkg.json")
	if hasVcpkg {
		backupPath := filepath.Join(backupDir, "vcpkg_backup.json")
		if err := utils.CopyFile(vcpkgPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup vcpkg.json: %v", err)
		}
		_ = utils.AppendLog(projectDir, "[CppHandler] Backed up existing vcpkg.json")
	}

	if err := WriteVcpkgJSON(vcpkgPath, deps); err != nil {
		return err
	}
	_ = utils.AppendLog(projectDir, "[CppHandler] Wrote updated vcpkg.json (fallback recovery)")

	// If the project uses build systems where vcpkg isn't native, inform via logs
	if hasCMake || hasBazel || hasMeson || hasMake || hasConfigure {
		_ = utils.AppendLog(projectDir, "[CppHandler] Note: Project uses native build system files (CMake/Bazel/Meson/Makefile/configure.ac).")
		_ = utils.AppendLog(projectDir, "[CppHandler] Wrote vcpkg.json as a fallback. Consider integrating these dependencies into the native build files manually.")
	}

	return nil
}

// ---------------------------
// Helper Functions & Parsers
// ---------------------------

// small helper
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// VcpkgJSON represents vcpkg.json
type VcpkgJSON struct {
	Name         string   `json:"name,omitempty"`
	Version      string   `json:"version,omitempty"`
	Dependencies []string `json:"dependencies"`
}

// ParseVcpkgJSON reads vcpkg.json and returns deps
func ParseVcpkgJSON(vcpkgPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(vcpkgPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}

	data, err := os.ReadFile(vcpkgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", vcpkgPath, err)
	}

	var vcpkg VcpkgJSON
	if err := json.Unmarshal(data, &vcpkg); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %v", vcpkgPath, err)
	}

	var deps []utils.Dependency
	for _, name := range vcpkg.Dependencies {
		deps = append(deps, utils.Dependency{
			GroupID:    "vcpkg",
			ArtifactID: name,
			Version:    "", // leave empty so ORT marks unknown rather than defaulting to latest
			Scope:      "compile",
			Key:        name,
		})
	}
	return deps, nil
}

// ParseConanFile reads conanfile.txt
func ParseConanFile(conanPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(conanPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}

	file, err := os.Open(conanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", conanPath, err)
	}
	defer file.Close()

	var deps []utils.Dependency
	scanner := bufio.NewScanner(file)
	inReq := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[requires]" {
			inReq = true
			continue
		}
		if strings.HasPrefix(line, "[") && line != "[requires]" {
			inReq = false
		}
		if inReq && line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, "/")
			name := parts[0]
			version := ""
			if len(parts) > 1 {
				version = parts[1]
			}
			deps = append(deps, utils.Dependency{
				GroupID:    "conan",
				ArtifactID: name,
				Version:    version,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", conanPath, err)
	}
	return deps, nil
}

// ParseConanPy tries to extract requires from a conanfile.py using simple regex heuristics
func ParseConanPy(conanPyPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(conanPyPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(conanPyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", conanPyPath, err)
	}
	// look for patterns like: requires = "pkg/1.2.3" or self.requires = "pkg/1.2" or ["pkg/1.2", "other/2.0"]
	reSingle := regexp.MustCompile(`(?m)(?:requires\s*=\s*|self\.requires\s*=\s*)["']([^"']+)["']`)
	reList := regexp.MustCompile(`(?m)(?:requires\s*=\s*|self\.requires\s*=\s*)\[(.*?)\]`)
	matches := reSingle.FindAllSubmatch(data, -1)
	deps := make([]utils.Dependency, 0)
	for _, m := range matches {
		parts := strings.Split(string(m[1]), "/")
		name := parts[0]
		version := ""
		if len(parts) > 1 {
			version = parts[1]
		}
		deps = append(deps, utils.Dependency{
			GroupID:    "conan",
			ArtifactID: name,
			Version:    version,
			Scope:      "compile",
			Key:        name,
		})
	}
	// list style
	listMatches := reList.FindAllSubmatch(data, -1)
	for _, lm := range listMatches {
		content := string(lm[1])
		// split by commas and strip quotes
		items := regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(content, -1)
		for _, it := range items {
			parts := strings.Split(it[1], "/")
			name := parts[0]
			version := ""
			if len(parts) > 1 {
				version = parts[1]
			}
			deps = append(deps, utils.Dependency{
				GroupID:    "conan",
				ArtifactID: name,
				Version:    version,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	return deps, nil
}

// ParseCMakeLists extracts find_package and pkg-config style targets
func ParseCMakeLists(cmakePath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(cmakePath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(cmakePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", cmakePath, err)
	}
	text := string(data)
	deps := make([]utils.Dependency, 0)

	// find_package(Pkg [REQUIRED] [VERSION x.y]) -> capture Pkg
	reFind := regexp.MustCompile(`(?i)find_package\(\s*([A-Za-z0-9_\-]+)`)
	matches := reFind.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		name := m[1]
		deps = append(deps, utils.Dependency{
			GroupID:    "cmake",
			ArtifactID: name,
			Version:    "",
			Scope:      "compile",
			Key:        name,
		})
	}

	// target_link_libraries(myapp PUBLIC libname) -> capture simple tokens that look like libs
	reLink := regexp.MustCompile(`(?i)target_link_libraries\([^)]*\)`)
	linkMatches := reLink.FindAllString(text, -1)
	for _, lm := range linkMatches {
		// within parentheses extract tokens, skip keywords like PUBLIC/PRIVATE/INTERFACE
		content := lm
		content = strings.TrimPrefix(content, "target_link_libraries")
		content = strings.TrimSpace(content)
		content = strings.TrimPrefix(content, "(")
		content = strings.TrimSuffix(content, ")")
		parts := strings.Fields(content)
		for _, p := range parts {
			up := strings.ToUpper(p)
			if up == "PUBLIC" || up == "PRIVATE" || up == "INTERFACE" {
				continue
			}
			// skip targets that are the first token (target name) by a heuristic: if it appears as first in the list we skip it
			// (already coarse; still useful)
			deps = append(deps, utils.Dependency{
				GroupID:    "cmake",
				ArtifactID: p,
				Version:    "",
				Scope:      "compile",
				Key:        p,
			})
		}
	}

	return deps, nil
}

// ParseMakefile attempts to find pkg-config or plain libraries in LDFLAGS/LDLIBS
func ParseMakefile(makePath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(makePath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	file, err := os.Open(makePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", makePath, err)
	}
	defer file.Close()

	deps := make([]utils.Dependency, 0)
	scanner := bufio.NewScanner(file)
	rePkg := regexp.MustCompile(`pkg-config\s+--libs\s+([A-Za-z0-9\-\_]+)`)
	reLib := regexp.MustCompile(`-l([A-Za-z0-9\-\_]+)`)
	for scanner.Scan() {
		line := scanner.Text()
		if m := rePkg.FindStringSubmatch(line); len(m) == 2 {
			deps = append(deps, utils.Dependency{
				GroupID:    "make",
				ArtifactID: m[1],
				Version:    "",
				Scope:      "compile",
				Key:        m[1],
			})
		}
		if ms := reLib.FindAllStringSubmatch(line, -1); len(ms) > 0 {
			for _, mm := range ms {
				deps = append(deps, utils.Dependency{
					GroupID:    "make",
					ArtifactID: mm[1],
					Version:    "",
					Scope:      "compile",
					Key:        mm[1],
				})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", makePath, err)
	}
	return deps, nil
}

// ParseMesonBuild scans for dependency('name') calls
func ParseMesonBuild(mesonPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(mesonPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(mesonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", mesonPath, err)
	}
	reDep := regexp.MustCompile(`(?i)dependency\(\s*['"]?([A-Za-z0-9\-_]+)['"]?`)
	matches := reDep.FindAllStringSubmatch(string(data), -1)
	deps := make([]utils.Dependency, 0)
	for _, m := range matches {
		deps = append(deps, utils.Dependency{
			GroupID:    "meson",
			ArtifactID: m[1],
			Version:    "",
			Scope:      "compile",
			Key:        m[1],
		})
	}
	return deps, nil
}

// ParseBazelBUILD extracts simple deps in strings (heuristic)
func ParseBazelBUILD(buildPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(buildPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(buildPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", buildPath, err)
	}
	// Very simple heuristic: find strings that look like @repo//pkg:target or "libname"
	reStr := regexp.MustCompile(`["']([A-Za-z0-9@\-/\._:]+)["']`)
	matches := reStr.FindAllStringSubmatch(string(data), -1)
	deps := make([]utils.Dependency, 0)
	for _, m := range matches {
		raw := m[1]
		// ignore labels that are clearly local (start with ":" or contain "//:")
		if strings.HasPrefix(raw, ":") {
			continue
		}
		// include external-looking entries
		if strings.Contains(raw, "@") || strings.Contains(raw, "//") {
			deps = append(deps, utils.Dependency{
				GroupID:    "bazel",
				ArtifactID: raw,
				Version:    "",
				Scope:      "compile",
				Key:        raw,
			})
		}
	}
	return deps, nil
}

// ParseConfigureAC attempts to find AC_CHECK_LIB or PKG_CHECK_MODULES
func ParseConfigureAC(confPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(confPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(confPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", confPath, err)
	}
	text := string(data)
	deps := make([]utils.Dependency, 0)

	reAC := regexp.MustCompile(`(?i)AC_CHECK_LIB\(\s*([A-Za-z0-9\-_]+)`)
	matches := reAC.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		deps = append(deps, utils.Dependency{
			GroupID:    "autotools",
			ArtifactID: m[1],
			Version:    "",
			Scope:      "compile",
			Key:        m[1],
		})
	}

	rePKG := regexp.MustCompile(`(?i)PKG_CHECK_MODULES\(\s*[^,]+,\s*([A-Za-z0-9\-_]+)`)
	pkgMatches := rePKG.FindAllStringSubmatch(text, -1)
	for _, m := range pkgMatches {
		deps = append(deps, utils.Dependency{
			GroupID:    "autotools",
			ArtifactID: m[1],
			Version:    "",
			Scope:      "compile",
			Key:        m[1],
		})
	}

	return deps, nil
}

// CollectCppIncludes scans .c/.cpp/.cc/.cxx/.h/.hpp files for includes
func CollectCppIncludes(projectDir string) ([]string, error) {
	includeRegex := regexp.MustCompile(`^#include\s*["<]([^">]+)[">]`)
	includes := make(map[string]struct{})

	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// skip common external dirs (optional)
			base := filepath.Base(path)
			if base == "vendor" || base == "third_party" || base == "build" || base == "out" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !(ext == ".cpp" || ext == ".c" || ext == ".cc" || ext == ".cxx" || ext == ".h" || ext == ".hpp") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#include") {
				m := includeRegex.FindStringSubmatch(line)
				if len(m) == 2 {
					inc := m[1]
					// Only external includes (with "/") — preserves original behavior but collects more header names
					if strings.Contains(inc, "/") {
						// normalize (remove leading path segments like "boost/..." -> "boost")
						artifact := NormalizeIncludeToArtifact(inc)
						if artifact != "" {
							includes[artifact] = struct{}{}
						}
					}
				}
			}
		}
		return scanner.Err()
	})

	if err != nil {
		return nil, err
	}

	var list []string
	for k := range includes {
		list = append(list, k)
	}
	return list, nil
}

// NormalizeIncludeToArtifact converts include path to a coarse artifact id
// e.g. "boost/algorithm/string.hpp" -> "boost", "fmt/format.h" -> "fmt"
func NormalizeIncludeToArtifact(include string) string {
	if include == "" {
		return ""
	}
	parts := strings.Split(include, "/")
	if len(parts) == 0 {
		return ""
	}
	// take first part as artifact; strip extensions or header filenames
	candidate := parts[0]
	// strip any extension if present (unlikely in first part)
	candidate = strings.TrimSuffix(candidate, ".h")
	candidate = strings.TrimSuffix(candidate, ".hpp")
	candidate = strings.TrimSpace(candidate)
	// basic sanitize
	candidate = strings.Trim(candidate, "\"<> ")
	return candidate
}

// WriteVcpkgJSON writes dependencies to vcpkg.json
func WriteVcpkgJSON(vcpkgPath string, deps []utils.Dependency) error {
	var vcpkg VcpkgJSON
	seen := make(map[string]struct{})
	for _, d := range deps {
		// prefer artifact id if present
		name := d.ArtifactID
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		vcpkg.Dependencies = append(vcpkg.Dependencies, name)
		seen[name] = struct{}{}
	}

	// Provide a minimal name/version so vcpkg.json is well-formed and more likely to be recognized.
	if vcpkg.Name == "" {
		vcpkg.Name = "recovery"
	}
	if vcpkg.Version == "" {
		vcpkg.Version = "0.0.0"
	}

	data, err := json.MarshalIndent(vcpkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vcpkg.json: %v", err)
	}

	return os.WriteFile(vcpkgPath, data, 0644)
}

// WriteConanFile creates a minimal conanfile.txt with [requires]
func WriteConanFile(conanPath string, deps []utils.Dependency) error {
	// assemble unique requires
	seen := make(map[string]struct{})
	lines := []string{"[requires]"}
	for _, d := range deps {
		name := d.ArtifactID
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		if d.Version != "" {
			lines = append(lines, fmt.Sprintf("%s/%s", name, d.Version))
		} else {
			// leave version empty (just name), conan may require version but we'll keep it simple
			lines = append(lines, name)
		}
		seen[name] = struct{}{}
	}
	// add empty [generators] to be safe
	lines = append(lines, "", "[generators]", "cmake")
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(conanPath, []byte(content), 0644)
}
