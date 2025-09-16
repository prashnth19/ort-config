package utils

import (
	"os"
	"path/filepath"
	"strings"
)

type LanguageDetection struct {
	Language   string
	Confidence string   // High, Medium, Low
	Files      []string // Evidence files
}

var ignoreDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"venv":         true,
	"__pycache__":  true,
	"target":       true,
	"bin":          true,
	"obj":          true,
	"dist":         true,
	"build":        true,
	"coverage":     true,
	".idea":        true,
	".vscode":      true,
}

// EstimateLanguages walks the repo and detects supported languages.
func EstimateLanguages(repoPath string) ([]LanguageDetection, error) {
	var detections []LanguageDetection
	langMap := make(map[string]*LanguageDetection)

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // ignore error and continue
		}

		// Skip symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			return filepath.SkipDir
		}

		// Skip ignored directories
		if info.IsDir() && ignoreDirs[info.Name()] {
			return filepath.SkipDir
		}

		// Detect manifests first (High confidence)
		switch strings.ToLower(info.Name()) {
		case "pom.xml":
			addDetection(langMap, "java", "High", path)
		case "requirements.txt":
			addDetection(langMap, "python", "High", path)
		case "package.json":
			addDetection(langMap, "nodejs", "High", path)
		case "go.mod":
			addDetection(langMap, "go", "High", path)
		case "cargo.toml":
			addDetection(langMap, "rust", "High", path)
		case "gemfile":
			addDetection(langMap, "ruby", "High", path)
		case "composer.json":
			addDetection(langMap, "php", "High", path)
		case "packages.config", "project.assets.json":
			addDetection(langMap, "dotnet", "High", path)
		case "package.swift":
			addDetection(langMap, "swift", "High", path)
		case "c++_deps.txt": // hypothetical, we might extend later
			addDetection(langMap, "cpp", "High", path)
		}

		// Detect source files (Medium confidence if manifest not found)
		if !info.IsDir() {
			switch filepath.Ext(info.Name()) {
			case ".java":
				addDetection(langMap, "java", "Medium", path)
			case ".py":
				addDetection(langMap, "python", "Medium", path)
			case ".js", ".ts":
				addDetection(langMap, "nodejs", "Medium", path)
			case ".go":
				addDetection(langMap, "go", "Medium", path)
			case ".rs":
				addDetection(langMap, "rust", "Medium", path)
			case ".rb":
				addDetection(langMap, "ruby", "Medium", path)
			case ".php":
				addDetection(langMap, "php", "Medium", path)
			case ".cs", ".vb":
				addDetection(langMap, "dotnet", "Medium", path)
			case ".cpp", ".cc", ".cxx", ".h", ".hpp":
				addDetection(langMap, "cpp", "Medium", path)
			case ".swift":
				addDetection(langMap, "swift", "Medium", path)
			}
		}

		return nil
	})

	// Collect results
	for _, v := range langMap {
		detections = append(detections, *v)
	}

	return detections, err
}

// addDetection ensures we set confidence appropriately
func addDetection(langMap map[string]*LanguageDetection, lang string, confidence string, file string) {
	if existing, ok := langMap[lang]; ok {
		// Upgrade confidence if needed (High overrides Medium)
		if confidence == "High" && existing.Confidence != "High" {
			existing.Confidence = "High"
		}
		existing.Files = append(existing.Files, file)
	} else {
		langMap[lang] = &LanguageDetection{
			Language:   lang,
			Confidence: confidence,
			Files:      []string{file},
		}
	}
}
