package javahandler

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ort-recovery/utils"
)

// ---------------------------
// Java Handler (full-featured)
// ---------------------------
type JavaHandler struct{}

func (h *JavaHandler) Name() string {
	return "Java"
}

// Detect checks for Maven/Gradle manifests or any .java files (recursive)
func (h *JavaHandler) Detect(projectDir string) bool {
	manifests := []string{
		filepath.Join(projectDir, "pom.xml"),
		filepath.Join(projectDir, "build.gradle"),
		filepath.Join(projectDir, "build.gradle.kts"),
		filepath.Join(projectDir, "settings.gradle"),
	}
	for _, m := range manifests {
		if _, err := os.Stat(m); err == nil {
			return true
		}
	}

	// recursive scan for .java
	found := false
	_ = filepath.WalkDir(projectDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".java") {
			found = true
			return filepath.SkipDir
		}
		return nil
	})
	return found
}

// Scan: parse manifests (Maven + all Gradle files), collect imports recursively,
// consult syft.json, add missing deps (leave version empty if not found)
func (h *JavaHandler) Scan(projectDir string) ([]utils.Dependency, error) {
	var declaredDeps []utils.Dependency

	// 1) Parse Maven (pom.xml) if present
	pomPath := filepath.Join(projectDir, "pom.xml")
	if _, err := os.Stat(pomPath); err == nil {
		pdeps, err := ParsePom(pomPath)
		if err != nil {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Error parsing pom.xml: %v", err)
			return nil, err
		}
		declaredDeps = append(declaredDeps, pdeps...)
	}

	// 2) Parse all Gradle build files recursively
	gradleFiles := findAllFiles(projectDir, []string{"build.gradle", "build.gradle.kts"})
	for _, gf := range gradleFiles {
		gdeps, err := ParseGradle(gf)
		if err != nil {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Warning: failed to parse %s: %v", gf, err)
			// continue; parsing a single file shouldn't abort everything
			continue
		}
		declaredDeps = append(declaredDeps, gdeps...)
	}

	// 3) If settings.gradle exists, parse included modules and parse their build files too
	settingsPath := filepath.Join(projectDir, "settings.gradle")
	if _, err := os.Stat(settingsPath); err == nil {
		mods, err := ParseSettingsGradle(settingsPath)
		if err == nil {
			for _, mod := range mods {
				// attempt to parse module's build.gradle(.kts)
				modBuild := filepath.Join(projectDir, mod, "build.gradle")
				modBuildKts := filepath.Join(projectDir, mod, "build.gradle.kts")
				if _, e := os.Stat(modBuild); e == nil {
					if md, err := ParseGradle(modBuild); err == nil {
						declaredDeps = append(declaredDeps, md...)
					}
				} else if _, e2 := os.Stat(modBuildKts); e2 == nil {
					if md, err := ParseGradle(modBuildKts); err == nil {
						declaredDeps = append(declaredDeps, md...)
					}
				}
			}
		} else {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Warning: failed to parse settings.gradle: %v", err)
		}
	}

	// Normalize declared map
	declaredMap := make(map[string]utils.Dependency)
	for _, d := range declaredDeps {
		declaredMap[d.Key] = d
	}

	// 4) Collect imports recursively from repo (prefer scanning src/** but fallback to all .java)
	codeDeps, err := CollectJavaImports(projectDir)
	if err != nil {
		return nil, err
	}

	// 5) Parse syft.json (best-effort)
	syftMap := make(map[string]string)
	syftPath := filepath.Join(projectDir, "syft.json")
	if data, err := os.ReadFile(syftPath); err == nil {
		if sdeps, err := utils.ParseSyftJSON(data, "java"); err == nil {
			for _, s := range sdeps {
				// use key group:artifact as the index if available, else artifact-only
				if s.Key != "" {
					syftMap[s.Key] = s.Version
				}
				if s.ArtifactID != "" && syftMap[s.ArtifactID] == "" {
					syftMap[s.ArtifactID] = s.Version
				}
			}
		} else {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Warning: failed to parse syft.json: %v", err)
		}
	} else {
		_ = utils.AppendLog(projectDir, "[JavaHandler] No syft.json found; missing versions will be left empty so ORT marks them unknown.")
	}

	// 6) Build final list: keep declared, add missing from codeDeps
	finalDeps := declaredDeps
	seen := make(map[string]struct{})
	for _, d := range declaredDeps {
		seen[d.Key] = struct{}{}
	}

	for _, cd := range codeDeps {
		if _, ok := seen[cd.Key]; ok {
			continue
		}
		// Try mapping to canonical coordinates (map or heuristic)
		coord := MapImportToCoordinate(cd.ImportPath)
		if coord.GroupID != "" && coord.ArtifactID != "" {
			cd.GroupID = coord.GroupID
			cd.ArtifactID = coord.ArtifactID
			cd.Key = coord.GroupID + ":" + coord.ArtifactID
		} else {
			// fallback heuristic already applied in CollectJavaImports (group:artifact)
		}

		// Try syft for version using key or artifact
		version := ""
		if v, ok := syftMap[cd.Key]; ok && v != "" {
			version = v
		} else if v, ok := syftMap[cd.ArtifactID]; ok && v != "" {
			version = v
		}

		// Leave version empty if unknown (ORT will mark unknown) and log a note
		if version == "" {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Version unknown for %s; leaving empty so ORT marks as unknown.", cd.Key)
		} else {
			cd.Version = version
			_ = utils.AppendLog(projectDir, "[JavaHandler] Using version from Syft for %s: %s", cd.Key, version)
		}

		// final attributes
		cd.Scope = "compile"
		finalDeps = append(finalDeps, cd)
		seen[cd.Key] = struct{}{}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Added missing dependency: %s (version: %s)", cd.Key, cd.Version)
	}

	// If nothing declared and we have codeDeps, note intended build tool
	if len(declaredDeps) == 0 && len(codeDeps) > 0 {
		_ = utils.AppendLog(projectDir, "[JavaHandler] No declared build file found; will generate a recovery manifest with %d dependencies.", len(codeDeps))
	}

	return finalDeps, nil
}

// GenerateRecoveryFile: prefer Gradle if present (and unique), else Maven; handle multi-gradle gracefully
func (h *JavaHandler) GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error {
	// find manifests
	pomPath := filepath.Join(projectDir, "pom.xml")
	gradleFiles := findAllFiles(projectDir, []string{"build.gradle", "build.gradle.kts"})

	// If exactly one gradle file -> overwrite it (after backup)
	if len(gradleFiles) == 1 {
		gf := gradleFiles[0]
		if err := createBackup(gf, backupDir); err != nil {
			return err
		}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Backed up %s", filepath.Base(gf))
		kotlin := strings.HasSuffix(gf, ".kts")
		if err := WriteGradle(gf, deps, kotlin); err != nil {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Error writing %s: %v", gf, err)
			return err
		}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Wrote updated %s", filepath.Base(gf))
		return nil
	}

	// If multiple gradle files -> create a top-level fallback recovered gradle and log
	if len(gradleFiles) > 1 {
		backupErrors := []string{}
		for _, gf := range gradleFiles {
			if err := createBackup(gf, backupDir); err != nil {
				backupErrors = append(backupErrors, err.Error())
			}
		}
		if len(backupErrors) > 0 {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Warnings during Gradle backups: %v", strings.Join(backupErrors, "; "))
		}
		// write aggregated fallback
		outPath := filepath.Join(projectDir, "build.recovered.gradle")
		if err := WriteGradle(outPath, deps, false); err != nil {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Error writing %s: %v", outPath, err)
			return err
		}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Multiple Gradle files found; wrote aggregated build.recovered.gradle. Consider merging into module build files manually.")
		return nil
	}

	// Else if single pom exists -> write pom
	if _, err := os.Stat(pomPath); err == nil {
		if err := createBackup(pomPath, backupDir); err != nil {
			return err
		}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Backed up pom.xml")
		if err := WritePom(pomPath, deps); err != nil {
			_ = utils.AppendLog(projectDir, "[JavaHandler] Error writing pom.xml: %v", err)
			return err
		}
		_ = utils.AppendLog(projectDir, "[JavaHandler] Wrote updated pom.xml")
		return nil
	}

	// No manifests at all -> create a new pom.xml as default
	newPom := filepath.Join(projectDir, "pom.xml")
	if err := WritePom(newPom, deps); err != nil {
		_ = utils.AppendLog(projectDir, "[JavaHandler] Error writing fallback pom.xml: %v", err)
		return err
	}
	_ = utils.AppendLog(projectDir, "[JavaHandler] Created new pom.xml (fallback recovery)")
	return nil
}

// ---------------------------
// Helper Utilities
// ---------------------------

// createBackup copies src to backupDir with timestamp suffix
func createBackup(src, backupDir string) error {
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return nil
	}
	// ensure backupDir exists
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup dir: %v", err)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	dst := filepath.Join(backupDir, filepath.Base(src)+".bak."+ts)
	if err := utils.CopyFile(src, dst); err != nil {
		return fmt.Errorf("failed to backup %s -> %s: %v", src, dst, err)
	}
	return nil
}

// findAllFiles walks the tree and returns files matching any of the names in names
func findAllFiles(root string, names []string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		for _, n := range names {
			if base == n {
				found = append(found, p)
				break
			}
		}
		return nil
	})
	return found
}

// ---------------------------
// Maven Helpers
// ---------------------------

type Project struct {
	XMLName      xml.Name   `xml:"project"`
	Dependencies []MavenDep `xml:"dependencies>dependency"`
}

type MavenDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope,omitempty"`
}

func ParsePom(pomPath string) ([]utils.Dependency, error) {
	if _, err := os.Stat(pomPath); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pom.xml: %v", err)
	}
	var project Project
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("invalid pom.xml: %v", err)
	}
	var deps []utils.Dependency
	for _, d := range project.Dependencies {
		key := d.GroupID + ":" + d.ArtifactID
		scope := d.Scope
		if scope == "" {
			scope = "compile"
		}
		deps = append(deps, utils.Dependency{
			GroupID:    d.GroupID,
			ArtifactID: d.ArtifactID,
			Version:    d.Version,
			Scope:      scope,
			Key:        key,
		})
	}
	return deps, nil
}

func WritePom(pomPath string, deps []utils.Dependency) error {
	// Build a minimal POM with generated coordinates
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<project xmlns="http://maven.apache.org/POM/4.0.0"` + "\n")
	buf.WriteString(`         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` + "\n")
	buf.WriteString(`         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0` + "\n")
	buf.WriteString(`         http://maven.apache.org/xsd/maven-4.0.0.xsd">` + "\n")
	buf.WriteString("  <modelVersion>4.0.0</modelVersion>\n")
	buf.WriteString("  <groupId>generated</groupId>\n")
	buf.WriteString("  <artifactId>sbom-project</artifactId>\n")
	buf.WriteString("  <version>1.0.0</version>\n")
	buf.WriteString("  <dependencies>\n")

	seen := make(map[string]struct{})
	for _, d := range deps {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		key := d.GroupID + ":" + d.ArtifactID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		buf.WriteString("    <dependency>\n")
		buf.WriteString(fmt.Sprintf("      <groupId>%s</groupId>\n", d.GroupID))
		buf.WriteString(fmt.Sprintf("      <artifactId>%s</artifactId>\n", d.ArtifactID))
		if d.Version != "" {
			buf.WriteString(fmt.Sprintf("      <version>%s</version>\n", d.Version))
		} else {
			// leave out version so ORT can mark unknown, but add a comment
			buf.WriteString("      <!-- version intentionally left empty for ORT to mark unknown -->\n")
		}
		if d.Scope != "" && d.Scope != "compile" {
			buf.WriteString(fmt.Sprintf("      <scope>%s</scope>\n", d.Scope))
		}
		buf.WriteString("    </dependency>\n")
	}
	buf.WriteString("  </dependencies>\n")
	buf.WriteString("</project>\n")

	return os.WriteFile(pomPath, buf.Bytes(), 0644)
}

// ---------------------------
// Gradle Helpers
// ---------------------------

var gradleDepRegex = regexp.MustCompile(`(?i)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testCompile|annotationProcessor|compile)\s*\(?\s*['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?['"]\s*\)?`)

// ParseGradle parses a single build.gradle or build.gradle.kts for dependencies
func ParseGradle(path string) ([]utils.Dependency, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []utils.Dependency{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	var deps []utils.Dependency
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if m := gradleDepRegex.FindStringSubmatch(line); len(m) >= 4 {
			cfg := strings.ToLower(m[1])
			group := m[2]
			artifact := m[3]
			version := ""
			if len(m) >= 5 {
				version = m[4]
			}
			scope := "compile"
			if strings.Contains(cfg, "test") {
				scope = "test"
			}
			deps = append(deps, utils.Dependency{
				GroupID:    group,
				ArtifactID: artifact,
				Version:    version,
				Scope:      scope,
				Key:        group + ":" + artifact,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", path, err)
	}
	return deps, nil
}

// WriteGradle writes a Gradle file; if kotlinDSL==true writes .kts style
func WriteGradle(path string, deps []utils.Dependency, kotlinDSL bool) error {
	var b strings.Builder
	if kotlinDSL {
		b.WriteString("plugins {\n    id(\"java\")\n}\n\nrepositories {\n    mavenCentral()\n}\n\ndependencies {\n")
	} else {
		b.WriteString("plugins {\n    id 'java'\n}\n\nrepositories {\n    mavenCentral()\n}\n\ndependencies {\n")
	}

	seen := make(map[string]struct{})
	for _, d := range deps {
		if d.GroupID == "" || d.ArtifactID == "" {
			continue
		}
		key := d.GroupID + ":" + d.ArtifactID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		scope := "implementation"
		if d.Scope == "test" {
			scope = "testImplementation"
		}
		ver := d.Version
		if ver == "" {
			// leave version empty: write without version? Gradle requires version; we include a placeholder comment
			if kotlinDSL {
				b.WriteString(fmt.Sprintf("    // %s:%s - version unknown (left for ORT/maintainer)\n", d.GroupID, d.ArtifactID))
				b.WriteString(fmt.Sprintf("    %s(\"%s:%s:REPLACE_WITH_VERSION\")\n", scope, d.GroupID, d.ArtifactID))
			} else {
				b.WriteString(fmt.Sprintf("    // %s:%s - version unknown (left for ORT/maintainer)\n", d.GroupID, d.ArtifactID))
				b.WriteString(fmt.Sprintf("    %s '%s:%s:REPLACE_WITH_VERSION'\n", scope, d.GroupID, d.ArtifactID))
			}
			// no projectDir here; write to repo root recovery.log
			_ = utils.AppendLog(".", "[JavaHandler] WARNING: Gradle dependency %s has unknown version; wrote placeholder 'REPLACE_WITH_VERSION'.", key)
		} else {
			if kotlinDSL {
				b.WriteString(fmt.Sprintf("    %s(\"%s:%s:%s\")\n", scope, d.GroupID, d.ArtifactID, ver))
			} else {
				b.WriteString(fmt.Sprintf("    %s '%s:%s:%s'\n", scope, d.GroupID, d.ArtifactID, ver))
			}
		}
	}
	b.WriteString("}\n")
	return os.WriteFile(path, []byte(b.String()), 0644)
}

// ---------------------------
// Settings.gradle parser
// ---------------------------

var settingsIncludeRegex = regexp.MustCompile(`(?m)include\s+(.+)`)

// ParseSettingsGradle extracts included module paths like ':moduleA', then returns dir names
func ParseSettingsGradle(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}
	matches := settingsIncludeRegex.FindAllStringSubmatch(string(data), -1)
	var modules []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		// includes can be: include ':a', ':b'
		raw := m[1]
		parts := strings.Split(raw, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			p = strings.Trim(p, `"'`)
			p = strings.TrimSpace(p)
			// convert :module:submodule to module/submodule
			if strings.HasPrefix(p, ":") {
				p = strings.TrimPrefix(p, ":")
				p = strings.ReplaceAll(p, ":", string(filepath.Separator))
			}
			if p != "" {
				modules = append(modules, p)
			}
		}
	}
	return modules, nil
}

// ---------------------------
// Import scanning + mapping
// ---------------------------

// JavaImport holds an extracted import line
type JavaImport struct {
	ImportPath string // e.g., org.springframework.context.ApplicationContext
	GroupID    string
	ArtifactID string
	Key        string
	Version    string
}

// CollectJavaImports scans recursively and returns a list of JavaImport (unique by key)
func CollectJavaImports(projectDir string) ([]utils.Dependency, error) {
	importRegex := regexp.MustCompile(`^import\s+([a-zA-Z0-9_\.]+)(\.\*)?;`)

	found := make(map[string]JavaImport)
	// prefer src/** but fall back to repo-wide
	searchRoots := []string{
		filepath.Join(projectDir, "src"),
		projectDir,
	}
	walked := make(map[string]struct{})
	for _, root := range searchRoots {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".java") {
				return nil
			}
			// avoid scanning same file twice if projectDir==src
			if _, ok := walked[p]; ok {
				return nil
			}
			walked[p] = struct{}{}

			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "import ") {
					if m := importRegex.FindStringSubmatch(line); len(m) >= 2 {
						ip := m[1] // package path
						// map to coordinate or heuristic
						coord := MapImportToCoordinate(ip)
						key := ""
						if coord.GroupID != "" && coord.ArtifactID != "" {
							key = coord.GroupID + ":" + coord.ArtifactID
						} else {
							// fallback heuristic: group = first two tokens if available, artifact = third; else first:second
							parts := strings.Split(ip, ".")
							if len(parts) >= 3 {
								group := strings.Join(parts[:2], ".")
								artifact := parts[2]
								key = group + ":" + artifact
								coord.GroupID = group
								coord.ArtifactID = artifact
							} else if len(parts) >= 2 {
								group := parts[0]
								artifact := parts[1]
								key = group + ":" + artifact
								coord.GroupID = group
								coord.ArtifactID = artifact
							} else {
								// give up
								continue
							}
						}
						if _, ok := found[key]; !ok {
							found[key] = JavaImport{
								ImportPath: ip,
								GroupID:    coord.GroupID,
								ArtifactID: coord.ArtifactID,
								Key:        key,
							}
						}
					}
				}
			}
			return nil
		})
	}

	var deps []utils.Dependency
	for k, ji := range found {
		deps = append(deps, utils.Dependency{
			GroupID:    ji.GroupID,
			ArtifactID: ji.ArtifactID,
			Version:    "", // to be filled from syft in Scan
			Scope:      "compile",
			Key:        k,
		})
	}
	return deps, nil
}

// ---------------------------
// Mapping layer for imports -> Maven coordinates
// ---------------------------

// MapEntry is a mapping for a package prefix to coordinates
type MapEntry struct {
	GroupID    string
	ArtifactID string
}

// builtinImportMap contains common mappings; extend as you like
var builtinImportMap = map[string]MapEntry{
	"org.springframework":              {GroupID: "org.springframework", ArtifactID: "spring-context"},
	"org.springframework.web":          {GroupID: "org.springframework", ArtifactID: "spring-web"},
	"org.springframework.boot":         {GroupID: "org.springframework.boot", ArtifactID: "spring-boot-starter"},
	"com.google.gson":                  {GroupID: "com.google.code.gson", ArtifactID: "gson"},
	"com.fasterxml.jackson.databind":   {GroupID: "com.fasterxml.jackson.core", ArtifactID: "jackson-databind"},
	"com.fasterxml.jackson":            {GroupID: "com.fasterxml.jackson.core", ArtifactID: "jackson-databind"},
	"org.slf4j":                        {GroupID: "org.slf4j", ArtifactID: "slf4j-api"},
	"ch.qos.logback":                   {GroupID: "ch.qos.logback", ArtifactID: "logback-classic"},
	"junit.framework":                  {GroupID: "junit", ArtifactID: "junit"},
	"org.junit":                        {GroupID: "org.junit.jupiter", ArtifactID: "junit-jupiter-api"},
	"com.google.common":                {GroupID: "com.google.guava", ArtifactID: "guava"},
	"org.apache.commons.lang3":         {GroupID: "org.apache.commons", ArtifactID: "commons-lang3"},
	"org.apache.commons":               {GroupID: "org.apache.commons", ArtifactID: "commons-lang3"},
	"javax.servlet":                    {GroupID: "javax.servlet", ArtifactID: "javax.servlet-api"},
	"jakarta.servlet":                  {GroupID: "jakarta.servlet", ArtifactID: "jakarta.servlet-api"},
	"org.springframework.data.mongodb": {GroupID: "org.springframework.data", ArtifactID: "spring-data-mongodb"},
	"com.zaxxer.hikari":                {GroupID: "com.zaxxer", ArtifactID: "HikariCP"},
	"org.hibernate":                    {GroupID: "org.hibernate", ArtifactID: "hibernate-core"},
	"org.apache.logging.log4j":         {GroupID: "org.apache.logging.log4j", ArtifactID: "log4j-api"},
	"io.reactivex":                     {GroupID: "io.reactivex", ArtifactID: "rxjava"},
	"org.joda.time":                    {GroupID: "joda-time", ArtifactID: "joda-time"},
	"org.mockito":                      {GroupID: "org.mockito", ArtifactID: "mockito-core"},
	"com.zaxxer":                       {GroupID: "com.zaxxer", ArtifactID: "HikariCP"},
}

// MapImportToCoordinate looks up builtin map and returns best-effort coords
func MapImportToCoordinate(importPath string) MapEntry {
	// try longest-prefix match
	parts := strings.Split(importPath, ".")
	for i := len(parts); i >= 1; i-- {
		prefix := strings.Join(parts[:i], ".")
		if entry, ok := builtinImportMap[prefix]; ok {
			return entry
		}
	}
	// no builtin mapping found
	return MapEntry{}
}
