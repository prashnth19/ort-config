package utils

import (
	"regexp"
	"strings"
)

// Dependency represents a single dependency across all ecosystems
type Dependency struct {
	// General fields
	Name       string `json:"name,omitempty"`       // General dependency name (for Go/JS/Ruby/etc.)
	Version    string `json:"version,omitempty"`    // Version string
	ImportPath string `json:"importPath,omitempty"` // For Go/Java modules that require path resolution

	// Curation/merge fields
	Key        string `json:"key,omitempty"`        // Unique key (e.g., "group:artifact:version")
	GroupID    string `json:"groupId,omitempty"`    // For Java/Maven, crates, etc.
	ArtifactID string `json:"artifactId,omitempty"` // For Java/Maven, crates, etc.
	Scope      string `json:"scope,omitempty"`      // e.g., compile, test, runtime, build
	Language   string `json:"language,omitempty"`   // e.g., go, java, cpp, rust, swift
}

// Sanitize ensures the dependency data is valid for its ecosystem
func (d *Dependency) Sanitize() *Dependency {
	// Special handling for Go modules
	if d.Language == "go" {
		// Determine module path
		path := strings.TrimSpace(d.ImportPath)
		if path == "" {
			path = strings.TrimSpace(d.Name)
		}

		// Fallback: if still empty, skip this dependency
		if path == "" {
			return nil
		}

		// Clean up version
		version := strings.TrimSpace(d.Version)
		if version == "" {
			// default to "latest" if missing (Go will resolve this)
			version = "latest"
		} else {
			// Ensure version starts with 'v' or is semver-like
			if !strings.HasPrefix(version, "v") {
				version = "v" + version
			}
			// Strip invalid characters (only allow [0-9a-zA-Z._-])
			re := regexp.MustCompile(`[^0-9A-Za-z._\-+]`)
			version = re.ReplaceAllString(version, "")
			if version == "v" { // avoid "v" only
				version = "latest"
			}
		}

		// Return sanitized copy
		return &Dependency{
			Name:       d.Name,
			Version:    version,
			ImportPath: path,
			Key:        d.Key,
			GroupID:    d.GroupID,
			ArtifactID: d.ArtifactID,
			Scope:      d.Scope,
			Language:   d.Language,
		}
	}

	// For other ecosystems, return unchanged
	return d
}
