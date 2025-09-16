package gohandler

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"ort-recovery/utils"
)

// ---------------------------
// Go Handler
// ---------------------------
type GoHandler struct{}

func (h *GoHandler) Name() string {
	return "Go"
}

// Detect returns true if go.mod, go.work, or at least one .go file exists
func (h *GoHandler) Detect(projectDir string) bool {
	utils.AppendLog(projectDir, "[GoHandler][Detect] Checking for go.mod...")
	if _, err := os.Stat(filepath.Join(projectDir, "go.mod")); err == nil {
		utils.AppendLog(projectDir, "[GoHandler][Detect] go.mod found")
		return true
	}
	utils.AppendLog(projectDir, "[GoHandler][Detect] go.mod not found")

	utils.AppendLog(projectDir, "[GoHandler][Detect] Checking for go.work...")
	if _, err := os.Stat(filepath.Join(projectDir, "go.work")); err == nil {
		utils.AppendLog(projectDir, "[GoHandler][Detect] go.work found")
		return true
	}
	utils.AppendLog(projectDir, "[GoHandler][Detect] go.work not found")

	// fallback: detect any .go files
	utils.AppendLog(projectDir, "[GoHandler][Detect] Scanning for .go files...")
	found := false
	_ = filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			utils.AppendLog(projectDir, "[GoHandler][Detect] Walk error: %v", err)
			return nil
		}
		if info != nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".go") {
			utils.AppendLog(projectDir, "[GoHandler][Detect] Found Go file: %s", path)
			found = true
			return filepath.SkipDir // stop early once found
		}
		return nil
	})
	if found {
		utils.AppendLog(projectDir, "[GoHandler][Detect] At least one Go file found")
	}
	return found
}

// Scan parses go.mod, scans .go imports, and uses Syft only for metadata
func (h *GoHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	utils.AppendLog(projectDir, "[GoHandler][Scan] Start scan: %s", projectDir)

	modPath := filepath.Join(projectDir, "go.mod")
	var declaredDeps []utils.Dependency
	moduleName := ""

	// 1. Parse go.mod if exists
	if _, err := os.Stat(modPath); err == nil {
		utils.AppendLog(projectDir, "[GoHandler][Scan] go.mod exists, parsing...")
		parsedDeps, parsedModule, perr := ParseGoMod(modPath)
		if perr != nil {
			utils.AppendLog(projectDir, "[GoHandler][Scan] Error parsing go.mod: %v", perr)
			return nil, perr
		}
		declaredDeps = parsedDeps
		moduleName = parsedModule
		utils.AppendLog(projectDir, "[GoHandler][Scan] Parsed %d deps from go.mod; module=%s", len(parsedDeps), moduleName)
	} else {
		utils.AppendLog(projectDir, "[GoHandler][Scan] go.mod not found; will initialize later if required")
	}

	declaredMap := make(map[string]utils.Dependency)
	for _, d := range declaredDeps {
		declaredMap[sanitizeGoDep(d.ArtifactID)] = d
	}

	// 2. Collect imports from .go files (AST-based)
	utils.AppendLog(projectDir, "[GoHandler][Scan] Collecting imports via AST...")
	imports, err := CollectGoImports(projectDir, moduleName)
	if err != nil {
		utils.AppendLog(projectDir, "[GoHandler][Scan] Error collecting imports: %v", err)
		return nil, err
	}
	utils.AppendLog(projectDir, "[GoHandler][Scan] Collected %d unique imports", len(imports))

	// 3. Parse Syft output (metadata only)
	syftPath := filepath.Join(projectDir, "syft.json")
	utils.AppendLog(projectDir, "[GoHandler][Scan] Looking for syft.json at %s", syftPath)
	syftMap := make(map[string]string)
	if syftData, err := os.ReadFile(syftPath); err == nil {
		if syftDeps, perr := utils.ParseSyftJSON(syftData, "golang"); perr == nil {
			utils.AppendLog(projectDir, "[GoHandler][Scan] Parsed %d deps from syft.json", len(syftDeps))
			for _, d := range syftDeps {
				syftMap[sanitizeGoDep(d.ArtifactID)] = sanitizeGoDep(d.Version)
				utils.AppendLog(projectDir, "[GoHandler][Scan] Syft metadata: %s -> %s", d.ArtifactID, d.Version)
			}
		} else {
			utils.AppendLog(projectDir, "[GoHandler][Scan] Failed to parse syft.json: %v", perr)
		}
	} else {
		utils.AppendLog(projectDir, "[GoHandler][Scan] syft.json not found or unreadable: %v", err)
	}

	// 4. Build final dependency list
	final := make([]utils.Dependency, 0)
	seen := make(map[string]struct{})

	// Keep declared dependencies (preserve existing go.mod)
	utils.AppendLog(projectDir, "[GoHandler][Scan] Keeping declared dependencies (%d)", len(declaredDeps))
	for _, d := range declaredDeps {
		sanitized := sanitizeGoDep(d.ArtifactID)
		final = append(final, d)
		seen[sanitized] = struct{}{}
		utils.AppendLog(projectDir, "[GoHandler][Scan] Kept declared: %s %s", d.ArtifactID, d.Version)
	}

	// Add missing imports (AST) — prefer Syft version if present, otherwise "latest"
	utils.AppendLog(projectDir, "[GoHandler][Scan] Resolving missing imports from AST...")
	for _, imp := range imports {
		sanitizedImp := sanitizeGoDep(imp)
		if sanitizedImp == "" {
			continue
		}
		if _, ok := seen[sanitizedImp]; ok {
			utils.AppendLog(projectDir, "[GoHandler][Scan] Import already declared: %s", sanitizedImp)
			continue
		}
		version := "latest"
		if v, ok := syftMap[sanitizedImp]; ok && v != "" {
			version = sanitizeGoDep(v)
		}
		dep := utils.Dependency{
			GroupID:    "golang",
			ArtifactID: sanitizedImp,
			Version:    version,
			Scope:      "compile",
			Key:        sanitizedImp,
			Language:   "go",
		}
		if sanitized := dep.Sanitize(); sanitized != nil {
			final = append(final, *sanitized)
			seen[sanitizedImp] = struct{}{}
			if version == "latest" {
				utils.AppendLog(projectDir, "[GoHandler][Scan] Added missing dependency: %s (no Syft metadata)", sanitizedImp)
			} else {
				utils.AppendLog(projectDir, "[GoHandler][Scan] Added missing dependency: %s %s (from Syft)", sanitizedImp, version)
			}
		}
	}

	// Inform about missing go.mod with imports
	if len(declaredDeps) == 0 && len(imports) > 0 {
		utils.AppendLog(projectDir, "[GoHandler][Scan] No go.mod present and %d imports detected (will create go.mod during recovery)", len(imports))
	}

	utils.AppendLog(projectDir, "[GoHandler][Scan] Scan complete. Final deps: %d", len(final))
	return final, nil
}

// GenerateRecoveryFile writes new go.mod + regenerates go.sum
func (h *GoHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Starting recovery for: %s", projectDir)

	modPath := filepath.Join(projectDir, "go.mod")

	// Ensure go.mod exists (init if missing)
	if _, err := os.Stat(modPath); os.IsNotExist(err) {
		moduleName := filepath.Base(projectDir)
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go.mod missing, running: go mod init %s", moduleName)
		cmd := exec.Command("go", "mod", "init", moduleName)
		cmd.Dir = projectDir
		if out, err := cmd.CombinedOutput(); err != nil {
			utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go mod init failed: %v\nOutput:\n%s", err, string(out))
			return fmt.Errorf("failed to init go.mod: %v\nOutput:\n%s", err, string(out))
		}
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go.mod initialized")
	}

	// Extract module name (fallback to recovered/module)
	moduleName := getModulePath(modPath)
	if moduleName == "" {
		moduleName = "recovered/module"
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] module name fallback used: %s", moduleName)
	} else {
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] module name: %s", moduleName)
	}

	// Backup existing go.mod if present
	if _, err := os.Stat(modPath); err == nil {
		backupPath := filepath.Join(backupDir, "go.mod.bak")
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Backing up go.mod to %s", backupPath)
		if err := utils.CopyFile(modPath, backupPath); err != nil {
			utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Failed to backup go.mod: %v", err)
			return fmt.Errorf("failed to backup go.mod: %v", err)
		}
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go.mod backup complete")
	}

	// Write go.mod (we will skip writing entries whose version is "latest" — they will be resolved with 'go get <pkg>@latest')
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Writing go.mod (skipping entries with version 'latest')")
	if err := WriteGoMod(modPath, moduleName, deps); err != nil {
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] WriteGoMod failed: %v", err)
		return err
	}
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Wrote go.mod")

	// Resolve "latest" dependencies explicitly with go get
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Resolving 'latest' deps with go get")
	for _, d := range deps {
		if d.Version == "latest" || d.Version == "" {
			utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Running: go get %s@latest", d.ArtifactID)
			getCmd := exec.Command("go", "get", fmt.Sprintf("%s@latest", d.ArtifactID))
			getCmd.Dir = projectDir
			getOut, getErr := getCmd.CombinedOutput()
			if getErr != nil {
				utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go get failed for %s: %v\nOutput:\n%s", d.ArtifactID, getErr, string(getOut))
			} else {
				utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go get succeeded for %s", d.ArtifactID)
			}
		}
	}

	// Run go mod tidy
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] Running: go mod tidy")
	cmd := exec.Command("go", "mod", "tidy")
	cmd.Dir = projectDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go mod tidy failed: %v\nOutput:\n%s", err, string(output))
		return fmt.Errorf("go mod tidy failed: %v\nOutput:\n%s", err, string(output))
	}
	utils.AppendLog(projectDir, "[GoHandler][GenerateRecoveryFile] go mod tidy completed successfully")
	return nil
}

// ---------------------------
// Helpers
// ---------------------------

func ParseGoMod(modPath string) ([]utils.Dependency, string, error) {
	utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] Parsing go.mod: %s", modPath)
	if _, err := os.Stat(modPath); os.IsNotExist(err) {
		utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] go.mod does not exist")
		return []utils.Dependency{}, "", nil
	}

	file, err := os.Open(modPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open go.mod: %v", err)
	}
	defer file.Close()

	var deps []utils.Dependency
	moduleName := ""
	inRequireBlock := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// strip inline comments like: v1.2.3 // indirect
		if idx := strings.Index(line, "//"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "module") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				moduleName = sanitizeGoDep(parts[1])
				utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] Found module: %s", moduleName)
			}
			continue
		}

		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// single-line require: `require github.com/x v1.2.3`
		if strings.HasPrefix(line, "require ") && !inRequireBlock {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				dep := utils.Dependency{
					GroupID:    "golang",
					ArtifactID: sanitizeGoDep(parts[1]),
					Version:    sanitizeGoDep(parts[2]),
					Scope:      "compile",
					Key:        sanitizeGoDep(parts[1]),
					Language:   "go",
				}
				if sanitized := dep.Sanitize(); sanitized != nil {
					deps = append(deps, *sanitized)
					utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] Added single require: %s %s", dep.ArtifactID, dep.Version)
				}
			}
			continue
		}

		// inside require block: `github.com/x v1.2.3`
		if inRequireBlock && line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dep := utils.Dependency{
					GroupID:    "golang",
					ArtifactID: sanitizeGoDep(parts[0]),
					Version:    sanitizeGoDep(parts[1]),
					Scope:      "compile",
					Key:        sanitizeGoDep(parts[0]),
					Language:   "go",
				}
				if sanitized := dep.Sanitize(); sanitized != nil {
					deps = append(deps, *sanitized)
					utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] Added block require: %s %s", dep.ArtifactID, dep.Version)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", fmt.Errorf("failed to read go.mod: %v", err)
	}
	utils.AppendLog(filepath.Dir(modPath), "[GoHandler][ParseGoMod] Finished parsing go.mod. deps=%d module=%s", len(deps), moduleName)
	return deps, moduleName, nil
}

func CollectGoImports(projectDir string, modulePath string) ([]string, error) {
	utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Starting import collection in: %s", projectDir)
	imports := make(map[string]struct{})

	// Walk all subdirectories and parse each .go file's imports
	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Walk error: %v", werr)
			return nil
		}
		if info.IsDir() {
			base := strings.ToLower(info.Name())
			if base == "vendor" || base == ".git" {
				utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Skipping directory: %s", path)
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Parsing file: %s", path)
		fset := token.NewFileSet()
		node, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Parse error in %s: %v", path, parseErr)
			return nil
		}
		for _, imp := range node.Imports {
			pathVal := strings.Trim(imp.Path.Value, `"`)
			if pathVal == "" {
				continue
			}
			// skip module-local imports (exact match) and stdlib
			if modulePath != "" && pathVal == modulePath {
				utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Skipping module-local import: %s (file: %s)", pathVal, path)
				continue
			}
			if isStdLib(pathVal) {
				utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Skipping stdlib import: %s (file: %s)", pathVal, path)
				continue
			}
			clean := sanitizeGoDep(pathVal)
			if clean == "" {
				continue
			}
			imports[clean] = struct{}{}
			utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Found import: %s (file: %s)", clean, path)
		}
		return nil
	})
	if err != nil {
		utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Walk returned error: %v", err)
	}

	var list []string
	for k := range imports {
		list = append(list, k)
	}
	utils.AppendLog(projectDir, "[GoHandler][CollectGoImports] Completed import collection. Unique imports: %d", len(list))
	return list, nil
}

func WriteGoMod(modPath string, moduleName string, deps []utils.Dependency) error {
	utils.AppendLog(filepath.Dir(modPath), "[GoHandler][WriteGoMod] Writing go.mod: %s", modPath)
	f, err := os.Create(modPath)
	if err != nil {
		return fmt.Errorf("failed to create go.mod: %v", err)
	}
	defer f.Close()

	// module line
	if _, err := f.WriteString(fmt.Sprintf("module %s\n\n", moduleName)); err != nil {
		return fmt.Errorf("failed to write module line: %v", err)
	}

	if len(deps) > 0 {
		if _, err := f.WriteString("require (\n"); err != nil {
			return fmt.Errorf("failed to write require ( block: %v", err)
		}
		for _, d := range deps {
			if d.Version == "latest" || d.Version == "" {
				continue // skip writing "latest"
			}
			line := fmt.Sprintf("\t%s %s\n", d.ArtifactID, d.Version)
			if _, err := f.WriteString(line); err != nil {
				return fmt.Errorf("failed to write dependency: %v", err)
			}
			utils.AppendLog(filepath.Dir(modPath), "[GoHandler][WriteGoMod] Added dependency line: %s", strings.TrimSpace(line))
		}
		if _, err := f.WriteString(")\n"); err != nil {
			return fmt.Errorf("failed to close require block: %v", err)
		}
	}
	utils.AppendLog(filepath.Dir(modPath), "[GoHandler][WriteGoMod] go.mod written successfully")
	return nil
}

func getModulePath(modPath string) string {
	f, err := os.Open(modPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return sanitizeGoDep(parts[1])
			}
		}
	}
	return ""
}

// ---------------------------
// Utility helpers
// ---------------------------

func sanitizeGoDep(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, `"`, "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	return s
}

func isStdLib(path string) bool {
	// Standard library packages never contain a dot (.)
	// This heuristic is widely used and acceptable for recovery
	return !strings.Contains(path, ".")
}
