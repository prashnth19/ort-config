package dotnet

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ort-recovery/utils"
)

// ---------------------------
// .NET Handler
// ---------------------------
type DotNetHandler struct{}

func (h *DotNetHandler) Name() string {
	return ".NET"
}

// Detect returns true if any .NET project manifest exists
func (h *DotNetHandler) Detect(projectDir string) bool {
	globs := []string{
		"*.csproj",
		"*.vbproj",
		"packages.config",
		"project.json",
		"Directory.Packages.props",
	}
	for _, g := range globs {
		matches, _ := filepath.Glob(filepath.Join(projectDir, g))
		if len(matches) > 0 {
			return true
		}
	}
	return false
}

// Scan parses manifests, scans source files, resolves missing deps via Syft
func (h *DotNetHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// 1. Parse manifests
	if deps, _ := findAndParseCSProj(projectDir); len(deps) > 0 {
		declaredDeps = append(declaredDeps, deps...)
	}
	if deps, _ := findAndParseVBProj(projectDir); len(deps) > 0 {
		declaredDeps = append(declaredDeps, deps...)
	}
	if deps, _ := findAndParsePackagesConfig(projectDir); len(deps) > 0 {
		declaredDeps = append(declaredDeps, deps...)
	}
	if deps, _ := findAndParseProjectJSON(projectDir); len(deps) > 0 {
		declaredDeps = append(declaredDeps, deps...)
	}
	if deps, _ := findAndParseDirectoryPackagesProps(projectDir); len(deps) > 0 {
		declaredDeps = append(declaredDeps, deps...)
	}

	declaredMap := make(map[string]utils.Dependency)
	for _, d := range declaredDeps {
		declaredMap[d.ArtifactID] = d
	}

	// 2. Scan source files (.cs and .vb)
	imports, err := CollectDotNetImports(projectDir)
	if err != nil {
		return nil, err
	}

	// 3. Parse Syft output
	syftPath := filepath.Join(projectDir, "syft.json")
	data, err := os.ReadFile(syftPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read syft.json: %v", err)
	}
	syftDeps, err := utils.ParseSyftJSON(data, "dotnet")
	if err != nil {
		return nil, err
	}
	syftMap := make(map[string]string)
	for _, d := range syftDeps {
		syftMap[d.ArtifactID] = d.Version
	}

	// 4. Build final list
	final := make([]utils.Dependency, 0)
	seen := make(map[string]struct{})

	// Keep declared
	for _, d := range declaredDeps {
		final = append(final, d)
		seen[d.ArtifactID] = struct{}{}
	}

	// Add missing imports
	for _, imp := range imports {
		if _, ok := seen[imp]; ok {
			continue
		}
		version := "latest"
		if v, ok := syftMap[imp]; ok && v != "" {
			version = v
		}
		dep := utils.Dependency{
			GroupID:    "nuget",
			ArtifactID: imp,
			Version:    version,
			Scope:      "compile",
			Key:        imp,
		}
		final = append(final, dep)
		seen[imp] = struct{}{}

		if version == "latest" {
			_ = utils.AppendLog(projectDir, "[DotNetHandler] Added missing dependency: %s latest (no Syft version found)", imp)
		} else {
			_ = utils.AppendLog(projectDir, "[DotNetHandler] Added missing dependency: %s %s (from Syft)", imp, version)
		}
	}

	// If no manifest files but imports exist → new csproj
	if len(declaredDeps) == 0 && len(imports) > 0 {
		_ = utils.AppendLog(projectDir, "[DotNetHandler] No manifest found, creating new Recovered.csproj with %d dependencies.", len(imports))
	}

	return final, nil
}

// GenerateRecoveryFile writes updated manifest (backup included)
func (h *DotNetHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	// Pick a manifest to rewrite
	var manifestPath string
	var manifestType string
	choices := []struct {
		glob string
		typ  string
	}{
		{"*.csproj", "csproj"},
		{"*.vbproj", "vbproj"},
		{"packages.config", "packages"},
		{"project.json", "projectjson"},
		{"Directory.Packages.props", "props"},
	}
	for _, c := range choices {
		matches, _ := filepath.Glob(filepath.Join(projectDir, c.glob))
		if len(matches) > 0 {
			manifestPath = matches[0]
			manifestType = c.typ
			break
		}
	}
	if manifestPath == "" {
		// default fallback
		manifestPath = filepath.Join(projectDir, "Recovered.csproj")
		manifestType = "csproj"
		_ = utils.AppendLog(projectDir, "[DotNetHandler] Creating new Recovered.csproj")
	}

	// Backup if exists
	if _, err := os.Stat(manifestPath); err == nil {
		backupPath := filepath.Join(backupDir, filepath.Base(manifestPath)+".bak")
		if err := utils.CopyFile(manifestPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup %s: %v", manifestPath, err)
		}
		_ = utils.AppendLog(projectDir, "[DotNetHandler] Backed up existing %s", filepath.Base(manifestPath))
	}

	// Write updated manifest
	var err error
	switch manifestType {
	case "csproj", "vbproj":
		err = WriteCSProj(manifestPath, deps)
	case "packages":
		err = WritePackagesConfig(manifestPath, deps)
	case "projectjson":
		err = WriteProjectJSON(manifestPath, deps)
	case "props":
		err = WriteDirectoryPackagesProps(manifestPath, deps)
	}
	if err != nil {
		return err
	}
	_ = utils.AppendLog(projectDir, "[DotNetHandler] Wrote updated %s", filepath.Base(manifestPath))
	return nil
}

// ---------------------------
// Helper Functions
// ---------------------------

// ====== CSProj / VBProj ======
type CSProj struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []ItemGroup `xml:"ItemGroup"`
}
type ItemGroup struct {
	Packages []Package `xml:"PackageReference"`
}
type Package struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

func findAndParseCSProj(projectDir string) ([]utils.Dependency, error) {
	matches, _ := filepath.Glob(filepath.Join(projectDir, "*.csproj"))
	if len(matches) == 0 {
		return []utils.Dependency{}, nil
	}
	return ParseCSProj(matches[0])
}
func findAndParseVBProj(projectDir string) ([]utils.Dependency, error) {
	matches, _ := filepath.Glob(filepath.Join(projectDir, "*.vbproj"))
	if len(matches) == 0 {
		return []utils.Dependency{}, nil
	}
	return ParseCSProj(matches[0]) // same format as csproj
}
func ParseCSProj(csprojPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(csprojPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(csprojPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", csprojPath, err)
	}
	var proj CSProj
	if err := xml.Unmarshal(data, &proj); err != nil {
		return nil, fmt.Errorf("invalid XML in %s: %v", csprojPath, err)
	}
	var deps []utils.Dependency
	for _, ig := range proj.ItemGroups {
		for _, p := range ig.Packages {
			deps = append(deps, utils.Dependency{
				GroupID:    "nuget",
				ArtifactID: p.Include,
				Version:    p.Version,
				Scope:      "compile",
				Key:        p.Include,
			})
		}
	}
	return deps, nil
}
func WriteCSProj(csprojPath string, deps []utils.Dependency) error {
	var itemGroup ItemGroup
	for _, d := range deps {
		itemGroup.Packages = append(itemGroup.Packages, Package{
			Include: d.ArtifactID,
			Version: d.Version,
		})
	}
	proj := CSProj{ItemGroups: []ItemGroup{itemGroup}}
	data, err := xml.MarshalIndent(proj, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal XML: %v", err)
	}
	xmlHeader := []byte(xml.Header)
	data = append(xmlHeader, data...)
	return os.WriteFile(csprojPath, data, 0644)
}

// ====== packages.config ======
type PackagesConfig struct {
	XMLName xml.Name            `xml:"packages"`
	Pkgs    []PackagesConfigPkg `xml:"package"`
}
type PackagesConfigPkg struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

func findAndParsePackagesConfig(projectDir string) ([]utils.Dependency, error) {
	path := filepath.Join(projectDir, "packages.config")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pc PackagesConfig
	if err := xml.Unmarshal(data, &pc); err != nil {
		return nil, fmt.Errorf("invalid XML in packages.config: %v", err)
	}
	var deps []utils.Dependency
	for _, p := range pc.Pkgs {
		deps = append(deps, utils.Dependency{
			GroupID:    "nuget",
			ArtifactID: p.ID,
			Version:    p.Version,
			Scope:      "compile",
			Key:        p.ID,
		})
	}
	return deps, nil
}
func WritePackagesConfig(path string, deps []utils.Dependency) error {
	var pc PackagesConfig
	for _, d := range deps {
		pc.Pkgs = append(pc.Pkgs, PackagesConfigPkg{
			ID:      d.ArtifactID,
			Version: d.Version,
		})
	}
	data, err := xml.MarshalIndent(pc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal packages.config: %v", err)
	}
	xmlHeader := []byte(xml.Header)
	data = append(xmlHeader, data...)
	return os.WriteFile(path, data, 0644)
}

// ====== project.json ======
type ProjectJSON struct {
	Dependencies map[string]string `json:"dependencies"`
}

func findAndParseProjectJSON(projectDir string) ([]utils.Dependency, error) {
	path := filepath.Join(projectDir, "project.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pj ProjectJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return nil, fmt.Errorf("invalid JSON in project.json: %v", err)
	}
	var deps []utils.Dependency
	for name, version := range pj.Dependencies {
		if version == "" {
			version = "latest"
		}
		deps = append(deps, utils.Dependency{
			GroupID:    "nuget",
			ArtifactID: name,
			Version:    version,
			Scope:      "compile",
			Key:        name,
		})
	}
	return deps, nil
}
func WriteProjectJSON(path string, deps []utils.Dependency) error {
	pj := ProjectJSON{Dependencies: map[string]string{}}
	for _, d := range deps {
		pj.Dependencies[d.ArtifactID] = d.Version
	}
	data, err := json.MarshalIndent(pj, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal project.json: %v", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ====== Directory.Packages.props ======
type DirectoryPackagesProps struct {
	XMLName xml.Name                   `xml:"Project"`
	ItemGrp DirectoryPackagesItemGroup `xml:"ItemGroup"`
}
type DirectoryPackagesItemGroup struct {
	Packages []DirectoryPackageVersion `xml:"PackageVersion"`
}
type DirectoryPackageVersion struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

func findAndParseDirectoryPackagesProps(projectDir string) ([]utils.Dependency, error) {
	path := filepath.Join(projectDir, "Directory.Packages.props")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var props DirectoryPackagesProps
	if err := xml.Unmarshal(data, &props); err != nil {
		return nil, fmt.Errorf("invalid XML in Directory.Packages.props: %v", err)
	}
	var deps []utils.Dependency
	for _, p := range props.ItemGrp.Packages {
		deps = append(deps, utils.Dependency{
			GroupID:    "nuget",
			ArtifactID: p.Include,
			Version:    p.Version,
			Scope:      "compile",
			Key:        p.Include,
		})
	}
	return deps, nil
}
func WriteDirectoryPackagesProps(path string, deps []utils.Dependency) error {
	var itemGroup DirectoryPackagesItemGroup
	for _, d := range deps {
		itemGroup.Packages = append(itemGroup.Packages, DirectoryPackageVersion{
			Include: d.ArtifactID,
			Version: d.Version,
		})
	}
	props := DirectoryPackagesProps{ItemGrp: itemGroup}
	data, err := xml.MarshalIndent(props, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Directory.Packages.props: %v", err)
	}
	xmlHeader := []byte(xml.Header)
	data = append(xmlHeader, data...)
	return os.WriteFile(path, data, 0644)
}

// ====== Collect Imports (.cs + .vb) ======
func CollectDotNetImports(projectDir string) ([]string, error) {
	usingRegex := regexp.MustCompile(`^using\s+([\w\.]+);`)
	importsRegex := regexp.MustCompile(`^Imports\s+([\w\.]+)`)
	imports := make(map[string]struct{})

	err := filepath.Walk(projectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !(strings.HasSuffix(path, ".cs") || strings.HasSuffix(path, ".vb")) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if m := usingRegex.FindStringSubmatch(line); len(m) == 2 {
				ns := strings.Split(m[1], ".")[0]
				imports[ns] = struct{}{}
			}
			if m := importsRegex.FindStringSubmatch(line); len(m) == 2 {
				ns := strings.Split(m[1], ".")[0]
				imports[ns] = struct{}{}
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
	return list, nil
}
