package utils

import "fmt"

// Handler interface every language handler must implement
type Handler interface {
	Name() string
	Detect(projectPath string) bool
	Scan(projectPath string) ([]Dependency, error)
	GenerateRecoveryFile(deps []Dependency, projectPath, backupDir string) error
}

var handlers []Handler

// RegisterHandler registers a language handler
func RegisterHandler(h Handler) {
	handlers = append(handlers, h)
}

// GetHandlers returns all registered handlers
func GetHandlers() []Handler {
	if len(handlers) == 0 {
		fmt.Println("No handlers registered yet.")
	}
	return handlers
}
