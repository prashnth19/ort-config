package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Logger wraps Go's standard log with file and console output
type Logger struct {
	Info  *log.Logger
	Error *log.Logger
	File  *os.File
	Path  string
}

// NewLogger initializes loggers for info and error messages
func NewLogger() (*Logger, error) {
	// Ensure logs directory exists
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Create timestamped log file
	timestamp := time.Now().Format("20060102_150405")
	logFile := filepath.Join("logs", "recovery_"+timestamp+".log")

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %v", logFile, err)
	}

	return &Logger{
		Info:  log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile),
		Error: log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile),
		File:  file,
		Path:  logFile,
	}, nil
}

// Infof logs informational messages (console + file)
func (l *Logger) Infof(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...) // Console
	l.Info.Printf(format, v...)        // File
}

// Errorf logs error messages (console + file)
func (l *Logger) Errorf(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...) // Console
	l.Error.Printf(format, v...)        // File
}

// Close closes the log file when done
func (l *Logger) Close() {
	if l.File != nil {
		l.File.Close()
	}
}

// AppendLog writes a single line to recovery.log inside a project directory
// This is mainly for backward compatibility with handler calls
func AppendLog(projectDir, format string, args ...interface{}) error {
	logPath := filepath.Join(projectDir, "recovery.log")

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %v", logPath, err)
	}
	defer f.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf(format, args...)
	_, err = fmt.Fprintf(f, "[%s] %s\n", timestamp, line)
	return err
}
