package utils

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// CurationRule represents a single fix/override in master_curations.yml
type CurationRule struct {
	Key         string `yaml:"key"`         // groupID:artifactID
	Version     string `yaml:"version"`     // optional override
	Scope       string `yaml:"scope"`       // optional, e.g., test/compile
	Artifact    string `yaml:"artifact"`    // optional override for artifactID
	Group       string `yaml:"group"`       // optional override for groupID
	Proprietary bool   `yaml:"proprietary"` // optional flag for proprietary packages
}

// ApplyCurations applies master_curations.yml rules to the list of dependencies
func ApplyCurations(deps []Dependency, curationFile string) ([]Dependency, error) {
	data, err := os.ReadFile(curationFile) // ✅ replaces ioutil.ReadFile
	if err != nil {
		return nil, fmt.Errorf("failed to read curation file: %v", err)
	}

	var rules []CurationRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse curation file: %v", err)
	}

	// Map rules by key for quick lookup
	ruleMap := make(map[string]CurationRule)
	for _, r := range rules {
		ruleMap[r.Key] = r
	}

	// Apply rules
	for i, d := range deps {
		if rule, ok := ruleMap[d.Key]; ok {
			if rule.Version != "" {
				deps[i].Version = rule.Version
			}
			if rule.Group != "" {
				deps[i].GroupID = rule.Group
			}
			if rule.Artifact != "" {
				deps[i].ArtifactID = rule.Artifact
			}
			if rule.Scope != "" {
				deps[i].Scope = rule.Scope
			}
			// Optional: handle Proprietary flag
		}
	}

	return deps, nil
}
