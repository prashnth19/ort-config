package utils

import (
	"encoding/json"
	"fmt"
	"strings"
)

type SyftOutput struct {
	Artifacts []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"artifacts"`
}

// ParseSyftJSON parses raw JSON output from Syft and returns a list of Dependencies
func ParseSyftJSON(data []byte, language string) ([]Dependency, error) {
	var result SyftOutput
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("invalid syft output: %v", err)
	}

	if len(result.Artifacts) == 0 {
		return nil, fmt.Errorf("no artifacts found in syft output")
	}

	var deps []Dependency
	for _, a := range result.Artifacts {
		groupID := "unknown.group"
		if strings.HasPrefix(a.PURL, "pkg:maven/") {
			parts := strings.Split(a.PURL, "/")
			if len(parts) >= 2 {
				groupID = parts[1]
			}
		}

		dep := Dependency{
			GroupID:    groupID,
			ArtifactID: a.Name,
			Version:    a.Version,
			Scope:      "compile",
			Key:        fmt.Sprintf("%s:%s", groupID, a.Name),
		}

		// Simple heuristic: test scope for certain file types (can extend per language)
		if strings.Contains(strings.ToLower(language), "java") && strings.Contains(strings.ToLower(a.Name), "test") {
			dep.Scope = "test"
		}

		deps = append(deps, dep)
	}

	return deps, nil
}
