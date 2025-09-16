package utils

import (
	"fmt"
)

// MergeDependencies merges developer-declared deps with Syft-extracted deps
// - Keeps declared dependencies
// - Adds missing ones from Syft
// - Deduplicates based on Key
func MergeDependencies(declared []Dependency, syftDeps []Dependency) []Dependency {
	merged := []Dependency{}
	seen := make(map[string]bool)

	// Add all declared dependencies first
	for _, d := range declared {
		merged = append(merged, d)
		seen[d.Key] = true
	}

	// Add Syft dependencies if not already declared
	for _, s := range syftDeps {
		if !seen[s.Key] {
			merged = append(merged, s)
			seen[s.Key] = true
		}
	}

	return merged
}

// Optional: Print dependencies for debugging
func PrintDependencies(deps []Dependency) {
	for _, d := range deps {
		fmt.Printf("Key: %s, GroupID: %s, ArtifactID: %s, Version: %s, Scope: %s\n",
			d.Key, d.GroupID, d.ArtifactID, d.Version, d.Scope)
	}
}
