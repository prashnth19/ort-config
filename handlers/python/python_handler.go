package pythonhandler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"ort-recovery/utils"
)

// ---------------------------
// Python Handler (unified)
// ---------------------------
type PythonHandler struct{}

func (h *PythonHandler) Name() string { return "Python" }

// Detect: any of the known manifests or any .py files
func (h *PythonHandler) Detect(projectDir string) bool {
	manifests := []string{"pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "Pipfile.lock", "environment.yml"}
	for _, m := range manifests {
		if _, err := os.Stat(filepath.Join(projectDir, m)); err == nil {
			return true
		}
	}
	pyMatches, _ := filepath.Glob(filepath.Join(projectDir, "*.py"))
	return len(pyMatches) > 0
}

// Scan: parse declared, scan code for imports, merge, use syft for versions, apply curations
func (h *PythonHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	manifest := h.detectManifest(projectDir)

	// 1) Parse declared deps from the chosen manifest (if any)
	var declared []utils.Dependency
	var err error
	switch manifest {
	case "pyproject.toml":
		declared, err = ParsePyProject(filepath.Join(projectDir, manifest))
	case "setup.py":
		declared, err = ParseSetupPy(filepath.Join(projectDir, manifest))
	case "requirements.txt":
		declared, err = ParseRequirements(filepath.Join(projectDir, manifest))
	case "Pipfile", "Pipfile.lock":
		// treat Pipfile.lock like Pipfile for declared dependencies (lock versions available)
		declared, err = ParsePipfile(filepath.Join(projectDir, manifest))
	case "environment.yml":
		declared, err = ParseCondaEnv(filepath.Join(projectDir, manifest))
	default:
		declared = []utils.Dependency{}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest (%s): %v", manifest, err)
	}

	// 2) Collect imports from .py files
	usedPkgs, err := CollectPythonImports(projectDir)
	if err != nil {
		return nil, fmt.Errorf("failed to scan .py files: %v", err)
	}

	// 3) Build declared map and syft map
	declaredMap := map[string]utils.Dependency{}
	for _, d := range declared {
		declaredMap[d.ArtifactID] = d
	}

	syftMap := map[string]string{}
	syftPath := filepath.Join(projectDir, "syft.json")
	if _, err := os.Stat(syftPath); err == nil {
		if data, err := os.ReadFile(syftPath); err == nil {
			if syftDeps, err := utils.ParseSyftJSON(data, "python"); err == nil {
				for _, sd := range syftDeps {
					// assume syft ArtifactID is package name
					syftMap[sd.ArtifactID] = sd.Version
				}
			}
		}
	}

	// 4) Build final dependencies: keep declared + add missing used packages
	finalMap := map[string]utils.Dependency{}
	for _, d := range declared {
		finalMap[d.ArtifactID] = d
	}

	for _, pkg := range usedPkgs {
		if _, ok := finalMap[pkg]; ok {
			continue // already declared
		}
		// resolve version: syft -> empty or "latest" depending on config
		version := ""
		if v, ok := syftMap[pkg]; ok && v != "" {
			version = v
		} else {
			// fallback: leave empty (unpinned) instead of using utils.Config.NoLatestFallback
			version = ""
		}

		dep := utils.Dependency{
			GroupID:    "pypi",
			ArtifactID: pkg,
			Version:    version,
			Scope:      "compile",
			Key:        pkg,
		}
		finalMap[pkg] = dep

		// log action
		if version == "" {
			utils.AppendLog(fmt.Sprintf("[PythonHandler] Added missing dependency: %s (version unknown)", pkg), "INFO")
		} else {
			utils.AppendLog(fmt.Sprintf("[PythonHandler] Added missing dependency: %s %s (from Syft or fallback)", pkg, version), "INFO")
		}
	}

	// 5) Convert map to slice (sorted)
	var final []utils.Dependency
	for _, d := range finalMap {
		final = append(final, d)
	}
	sort.Slice(final, func(i, j int) bool {
		return final[i].ArtifactID < final[j].ArtifactID
	})

	// 6) Optionally merge with syft and apply curations via utils
	// MergeDependencies can be used if you want syft-added extras integrated:
	// merged := utils.MergeDependencies(final, nil) // final already contains syft-derived versions
	final, err = utils.ApplyCurations(final, "configs/master_curations.yml")
	if err != nil {
		return nil, err
	}

	// 7) If no manifest was present but we discovered imports, log creation intention
	if manifest == "" && len(usedPkgs) > 0 {
		utils.AppendLog(fmt.Sprintf("[PythonHandler] No manifest found; will create requirements.txt with %d deps", len(usedPkgs)), "INFO")
	}

	return final, nil
}

// GenerateRecoveryFile: backup and write the correct manifest format
func (h *PythonHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	manifest := h.detectManifest(projectDir)
	if manifest == "" {
		// default to requirements.txt if none exists
		manifest = "requirements.txt"
	}

	targetPath := filepath.Join(projectDir, manifest)

	// backup original if present
	if _, err := os.Stat(targetPath); err == nil {
		backupPath := filepath.Join(backupDir, manifest+".bak")
		if err := utils.CopyFile(targetPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup %s: %v", manifest, err)
		}
		utils.AppendLog(fmt.Sprintf("[PythonHandler] Backed up %s -> %s", targetPath, backupPath), "INFO")
	}

	// write in native format
	switch manifest {
	case "pyproject.toml":
		if err := WritePyProject(targetPath, deps); err != nil {
			return err
		}
	case "setup.py":
		if err := WriteSetupPy(targetPath, deps); err != nil {
			return err
		}
	case "requirements.txt":
		if err := WriteRequirements(targetPath, deps); err != nil {
			return err
		}
	case "Pipfile", "Pipfile.lock":
		if err := WritePipfile(targetPath, deps); err != nil {
			return err
		}
	case "environment.yml":
		if err := WriteCondaEnv(targetPath, deps); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported manifest: %s", manifest)
	}

	utils.AppendLog(fmt.Sprintf("[PythonHandler] Wrote updated %s", manifest), "INFO")
	return nil
}

// ---------------------------
// Helpers & parsers/writers
// ---------------------------

// detectManifest: return first found manifest in priority order
func (h *PythonHandler) detectManifest(projectDir string) string {
	order := []string{"pyproject.toml", "setup.py", "requirements.txt", "Pipfile", "Pipfile.lock", "environment.yml"}
	for _, f := range order {
		if _, err := os.Stat(filepath.Join(projectDir, f)); err == nil {
			return f
		}
	}
	return ""
}

// CollectPythonImports scans .py files and extracts top-level package names (unique, sorted)
// heuristically ignores stdlib
func CollectPythonImports(projectDir string) ([]string, error) {
	imports := map[string]struct{}{}

	importRe := regexp.MustCompile(`^\s*import\s+([a-zA-Z0-9_\.]+)`)
	fromRe := regexp.MustCompile(`^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+`)

	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// skip virtual env folders
		if info.IsDir() && (strings.HasPrefix(info.Name(), "venv") || info.Name() == ".venv" || info.Name() == "env") {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".py") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil // ignore unreadable files
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if m := importRe.FindStringSubmatch(line); len(m) > 1 {
				root := packageRoot(m[1])
				if isExternalPyPackage(root) {
					imports[root] = struct{}{}
				}
			}
			if m := fromRe.FindStringSubmatch(line); len(m) > 1 {
				root := packageRoot(m[1])
				if isExternalPyPackage(root) {
					imports[root] = struct{}{}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var list []string
	for k := range imports {
		list = append(list, k)
	}
	sort.Strings(list)
	return list, nil
}

func packageRoot(pkg string) string {
	parts := strings.Split(pkg, ".")
	return parts[0]
}

// simple stdlib heuristic (non-exhaustive)
var stdlibCommon = map[string]struct{}{
	"sys": {}, "os": {}, "re": {}, "json": {}, "math": {}, "time": {}, "logging": {}, "itertools": {},
	"functools": {}, "typing": {}, "pathlib": {}, "subprocess": {}, "collections": {}, "concurrent": {},
	"threading": {}, "http": {}, "email": {}, "xml": {}, "asyncio": {}, "unittest": {}, "pkgutil": {},
	"inspect": {},
}

func isExternalPyPackage(name string) bool {
	if name == "" {
		return false
	}
	if _, ok := stdlibCommon[name]; ok {
		return false
	}
	// treat everything else as external (could be local module, but scanning deeper is heavy)
	return true
}

// ---------- requirements.txt ----------
func ParseRequirements(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []utils.Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, ver := splitReqLine(line)
		deps = append(deps, utils.Dependency{
			GroupID:    "pypi",
			ArtifactID: name,
			Version:    ver,
			Scope:      "compile",
			Key:        name,
		})
	}
	return deps, nil
}

func WriteRequirements(path string, deps []utils.Dependency) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, d := range deps {
		if d.Version == "" || d.Version == "latest" {
			// write unpinned if version empty or intentionally latest is used (user opted)
			_, _ = f.WriteString(d.ArtifactID + "\n")
		} else {
			_, _ = f.WriteString(fmt.Sprintf("%s==%s\n", d.ArtifactID, d.Version))
		}
	}
	return nil
}

func splitReqLine(line string) (string, string) {
	// support "pkg==1.2.3", "pkg>=1.2", "pkg"
	ops := []string{"==", ">=", "<=", "!=", ">", "<", "~="}
	for _, op := range ops {
		if strings.Contains(line, op) {
			parts := strings.SplitN(line, op, 2)
			return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	// fallback: if contains "=", handle as key=value (rare)
	if strings.Contains(line, "=") && !strings.Contains(line, "==") {
		parts := strings.SplitN(line, "=", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return line, ""
}

// ---------- pyproject.toml ----------
func ParsePyProject(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree := map[string]any{}
	if err := toml.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	// try PEP 621: [project] dependencies (array)
	if project, ok := tree["project"].(map[string]any); ok {
		if deps, ok := project["dependencies"].([]any); ok {
			return depsFromTomlArray(deps), nil
		}
	}
	// try poetry: [tool.poetry.dependencies] (table)
	if tool, ok := tree["tool"].(map[string]any); ok {
		if poetry, ok := tool["poetry"].(map[string]any); ok {
			if depTable, ok := poetry["dependencies"].(map[string]any); ok {
				return depsFromTomlTable(depTable), nil
			}
		}
	}
	return []utils.Dependency{}, nil
}

func depsFromTomlArray(arr []any) []utils.Dependency {
	var deps []utils.Dependency
	for _, it := range arr {
		if s, ok := it.(string); ok {
			name, ver := splitReqLine(s)
			deps = append(deps, utils.Dependency{
				GroupID:    "pypi",
				ArtifactID: name,
				Version:    ver,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	return deps
}

func depsFromTomlTable(tbl map[string]any) []utils.Dependency {
	var deps []utils.Dependency
	for k, v := range tbl {
		if k == "python" {
			continue
		}
		switch val := v.(type) {
		case string:
			name, ver := k, strings.Trim(val, `"' `)
			deps = append(deps, utils.Dependency{
				GroupID:    "pypi",
				ArtifactID: name,
				Version:    ver,
				Scope:      "compile",
				Key:        name,
			})
		case map[string]any:
			// poetry can specify { version = "^1.0" }
			if verRaw, ok := val["version"]; ok {
				if vs, ok := verRaw.(string); ok {
					deps = append(deps, utils.Dependency{
						GroupID:    "pypi",
						ArtifactID: k,
						Version:    strings.Trim(vs, `"' `),
						Scope:      "compile",
						Key:        k,
					})
				}
			}
		}
	}
	return deps
}

func WritePyProject(path string, deps []utils.Dependency) error {
	// minimal pyproject writer: [project] dependencies = [...]
	lines := []string{"[project]", "dependencies = ["}
	for _, d := range deps {
		if d.Version == "" || d.Version == "latest" {
			lines = append(lines, fmt.Sprintf("  \"%s\",", d.ArtifactID))
		} else {
			lines = append(lines, fmt.Sprintf("  \"%s==%s\",", d.ArtifactID, d.Version))
		}
	}
	lines = append(lines, "]")
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// ---------- setup.py (conservative parse/write) ----------
func ParseSetupPy(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)
	deps := []utils.Dependency{}
	// simple heuristic: find install_requires = [ ... ]
	idx := strings.Index(content, "install_requires")
	if idx == -1 {
		return deps, nil
	}
	blockStart := strings.Index(content[idx:], "[")
	blockEnd := strings.Index(content[idx:], "]")
	if blockStart == -1 || blockEnd == -1 || blockEnd <= blockStart {
		return deps, nil
	}
	block := content[idx+blockStart+1 : idx+blockEnd]
	for _, line := range strings.Split(block, ",") {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, `"' `)
		if line == "" {
			continue
		}
		name, ver := splitReqLine(line)
		deps = append(deps, utils.Dependency{
			GroupID:    "pypi",
			ArtifactID: name,
			Version:    ver,
			Scope:      "compile",
			Key:        name,
		})
	}
	return deps, nil
}

func WriteSetupPy(path string, deps []utils.Dependency) error {
	lines := []string{"from setuptools import setup", "", "setup(", "    install_requires=["}
	for _, d := range deps {
		if d.Version == "" || d.Version == "latest" {
			lines = append(lines, fmt.Sprintf("        \"%s\",", d.ArtifactID))
		} else {
			lines = append(lines, fmt.Sprintf("        \"%s==%s\",", d.ArtifactID, d.Version))
		}
	}
	lines = append(lines, "    ]", ")")
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// ---------- Pipfile (TOML) ----------
func ParsePipfile(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tree := map[string]any{}
	if err := toml.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	deps := []utils.Dependency{}
	if pkgs, ok := tree["packages"].(map[string]any); ok {
		for k, v := range pkgs {
			switch vv := v.(type) {
			case string:
				deps = append(deps, utils.Dependency{
					GroupID:    "pypi",
					ArtifactID: k,
					Version:    strings.Trim(vv, `"' `),
					Scope:      "compile",
					Key:        k,
				})
			case map[string]any:
				if verRaw, ok := vv["version"]; ok {
					if vs, ok := verRaw.(string); ok {
						deps = append(deps, utils.Dependency{
							GroupID:    "pypi",
							ArtifactID: k,
							Version:    strings.Trim(vs, `"' `),
							Scope:      "compile",
							Key:        k,
						})
					}
				}
			}
		}
	}
	return deps, nil
}

func WritePipfile(path string, deps []utils.Dependency) error {
	lines := []string{"[packages]"}
	for _, d := range deps {
		if d.Version == "" || d.Version == "latest" {
			lines = append(lines, fmt.Sprintf("%s = \"*\"", d.ArtifactID))
		} else {
			lines = append(lines, fmt.Sprintf("%s = \"%s\"", d.ArtifactID, d.Version))
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

// ---------- environment.yml (conda) ----------
type CondaEnv struct {
	Dependencies []interface{} `yaml:"dependencies"`
}

func ParseCondaEnv(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env CondaEnv
	if err := yaml.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	deps := []utils.Dependency{}
	for _, it := range env.Dependencies {
		if s, ok := it.(string); ok {
			parts := strings.SplitN(s, "=", 2)
			name := parts[0]
			ver := ""
			if len(parts) > 1 {
				ver = parts[1]
			}
			deps = append(deps, utils.Dependency{
				GroupID:    "pypi",
				ArtifactID: name,
				Version:    ver,
				Scope:      "compile",
				Key:        name,
			})
		}
	}
	return deps, nil
}

func WriteCondaEnv(path string, deps []utils.Dependency) error {
	env := CondaEnv{Dependencies: []interface{}{}}
	for _, d := range deps {
		entry := d.ArtifactID
		if d.Version != "" && d.Version != "latest" {
			entry += "=" + d.Version
		}
		env.Dependencies = append(env.Dependencies, entry)
	}
	out, err := yaml.Marshal(&env)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0644)
}
