package utils

// Config is used by some handlers (like Python) to store recovery settings
type Config struct {
	ProjectDir       string       // Path to the project being processed
	Dependencies     []Dependency // Dependencies found or reconciled
	NoLatestFallback bool         // If true, don't fallback to "latest" when version is missing
}
