package handlers

import (
	"fmt"

	cpphandler "ort-recovery/handlers/cpp"
	dotnethandler "ort-recovery/handlers/dotnet"
	gohandler "ort-recovery/handlers/go" // alias to avoid keyword clash
	javahandler "ort-recovery/handlers/java"
	nodehandler "ort-recovery/handlers/node"
	phphandler "ort-recovery/handlers/php"
	pythonhandler "ort-recovery/handlers/python"
	rubyhandler "ort-recovery/handlers/ruby"
	rusthandler "ort-recovery/handlers/rust"
	swifthandler "ort-recovery/handlers/swift"

	"ort-recovery/utils"
)

// Handler defines a common interface for all language handlers.
type Handler interface {
	Name() string
	Detect(projectDir string) bool
	Scan(projectDir string) ([]utils.Dependency, error)
	GenerateRecoveryFile(deps []utils.Dependency, projectDir, backupDir string) error
}

// GetHandlers returns all registered handlers and logs their registration.
func GetHandlers() []Handler {
	handlers := []Handler{
		&javahandler.JavaHandler{},
		&gohandler.GoHandler{},
		&pythonhandler.PythonHandler{},
		&nodehandler.NodeHandler{},
		&rusthandler.RustHandler{},
		&dotnethandler.DotNetHandler{},
		&rubyhandler.RubyHandler{},
		&phphandler.PHPHandler{},
		&cpphandler.CppHandler{},
		&swifthandler.SwiftHandler{},
	}

	for _, h := range handlers {
		utils.AppendLog("", fmt.Sprintf("[Init] Registered handler: %s", h.Name()))
	}

	return handlers
}
