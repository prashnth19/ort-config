package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"ort-recovery/handlers"
	"ort-recovery/utils"
)

// RepoEntry describes an input repo entry
type RepoEntry struct {
	Repo    string `json:"repo"`
	Branch  string `json:"branch,omitempty"`
	Product string `json:"product,omitempty"`
}

// ---------------------------
// Run Syft (v1.32.0+)
// ---------------------------
func runSyft(logger *utils.Logger, syftPath, projectDir string, verbose bool) error {
	syftJSON := filepath.Join(projectDir, "syft.json")

	// Always remove stale syft.json before scanning
	if _, err := os.Stat(syftJSON); err == nil {
		if verbose {
			logger.Infof("Removing stale %s before new scan", syftJSON)
		}
		_ = os.Remove(syftJSON)
	}

	args := []string{"scan", projectDir, "-o", fmt.Sprintf("json=%s", syftJSON)}
	if verbose {
		logger.Infof("Running: %s %v", syftPath, args)
	}

	cmd := exec.Command(syftPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Cleanup if syft failed
		_ = os.Remove(syftJSON)
		return fmt.Errorf("syft execution failed: %v\nOutput:\n%s", err, string(output))
	}

	if _, err := os.Stat(syftJSON); os.IsNotExist(err) {
		return fmt.Errorf("syft ran but syft.json not found in %s\nOutput:\n%s", projectDir, string(output))
	}

	return nil
}

// ---------------------------
// Git clone helper
// ---------------------------
//
// Behavior (conservative, non-invasive):
//   - If branch is provided, first try `git clone -b <branch> repo clonePath`.
//   - If that fails (branch not present or clone error), remove any partial clone
//     and fall back to plain `git clone repo clonePath` which uses the remote's
//     default branch. If both attempts fail, return an error with combined output.
func cloneRepo(repoURL, branch, tempRoot string) (string, error) {
	repoName := filepath.Base(repoURL)
	ext := filepath.Ext(repoName)
	if ext != "" {
		repoName = repoName[:len(repoName)-len(ext)]
	}
	clonePath := filepath.Join(tempRoot, fmt.Sprintf("%s_%d", repoName, time.Now().Unix()))

	// helper to run git command and return output+error
	runGit := func(args ...string) ([]byte, error) {
		cmd := exec.Command("git", args...)
		return cmd.CombinedOutput()
	}

	// If a branch was requested, attempt clone with -b first.
	if branch != "" {
		args := []string{"clone", "-b", branch, repoURL, clonePath}
		out, err := runGit(args...)
		if err == nil {
			return clonePath, nil
		}

		// first attempt failed; try fallback to default-branch clone
		// remove any partial clone directory before retrying
		_ = os.RemoveAll(clonePath)

		// fallback attempt: plain clone (uses remote default branch)
		out2, err2 := runGit("clone", repoURL, clonePath)
		if err2 == nil {
			return clonePath, nil
		}

		// both failed — include both outputs for debugging
		return "", fmt.Errorf("git clone failed (branch attempt): %v\noutput:\n%s\n\nfallback plain clone failed: %v\noutput:\n%s", err, string(out), err2, string(out2))
	}

	// No branch requested — do plain clone
	out, err := runGit("clone", repoURL, clonePath)
	if err != nil {
		return "", fmt.Errorf("git clone failed: %v\noutput: %s", err, string(out))
	}
	return clonePath, nil
}

// ---------------------------
// Process project
// ---------------------------
func processProject(logger *utils.Logger, syftPath, projectDir, backupDir string, verbose bool) {
	absProject, err := filepath.Abs(projectDir)
	if err != nil {
		logger.Errorf("failed to resolve project path: %v", err)
		return
	}

	if verbose {
		logger.Infof("Processing project: %s", absProject)
	}

	// ✅ Run go mod tidy first (only if Go project)
	goModPath := filepath.Join(absProject, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		if verbose {
			logger.Infof("Running 'go mod tidy' in %s", absProject)
		}
		cmd := exec.Command("go", "mod", "tidy")
		cmd.Dir = absProject
		output, err := cmd.CombinedOutput()
		if err != nil {
			logger.Errorf("go mod tidy failed in %s: %v\nOutput:\n%s", absProject, err, string(output))
		} else if verbose {
			logger.Infof("go mod tidy completed successfully")
		}
	}

	// Run Syft
	if verbose {
		logger.Infof("Running Syft in %s", absProject)
	}
	if err := runSyft(logger, syftPath, absProject, verbose); err != nil {
		logger.Errorf("Syft failed for %s: %v", absProject, err)
	}

	handlersList := handlers.GetHandlers()
	if len(handlersList) == 0 {
		logger.Infof("No language handlers registered.")
		return
	}

	type result struct {
		Name    string
		Found   bool
		Added   int
		Errored bool
		Err     error
	}
	var summary []result

	for _, h := range handlersList {
		name := h.Name()
		if verbose {
			logger.Infof("Checking handler: %s", name)
		}

		if !h.Detect(absProject) {
			if verbose {
				logger.Infof("Handler %s: not detected in project", name)
			}
			summary = append(summary, result{Name: name, Found: false})
			continue
		}

		if verbose {
			logger.Infof("Handler %s: detected. Scanning...", name)
		}

		deps, err := h.Scan(absProject)
		if err != nil {
			logger.Errorf("Handler %s: scan error: %v", name, err)
			summary = append(summary, result{Name: name, Found: true, Errored: true, Err: err})
			continue
		}

		if len(deps) == 0 {
			if verbose {
				logger.Infof("Handler %s: no dependencies found.", name)
			}
			summary = append(summary, result{Name: name, Found: true, Added: 0})
			continue
		}

		if verbose {
			logger.Infof("Handler %s: generating recovery file (deps: %d)...", name, len(deps))
		}

		// Backup dir per handler
		repoBackupDir := filepath.Join(backupDir, filepath.Base(absProject), name)
		if err := os.MkdirAll(repoBackupDir, 0o755); err != nil {
			logger.Errorf("Failed to create backup dir %s: %v", repoBackupDir, err)
			continue
		}

		if err := h.GenerateRecoveryFile(deps, absProject, repoBackupDir); err != nil {
			logger.Errorf("Handler %s: error generating recovery file: %v", name, err)
			summary = append(summary, result{Name: name, Found: true, Errored: true, Err: err})
			continue
		}

		added := utils.GetAddedCountForLastHandler(name)
		summary = append(summary, result{Name: name, Found: true, Added: added})
	}

	// Cleanup syft.json after handlers finish
	syftJSON := filepath.Join(absProject, "syft.json")
	if _, err := os.Stat(syftJSON); err == nil {
		if verbose {
			logger.Infof("Cleaning up %s after processing", syftJSON)
		}
		_ = os.Remove(syftJSON)
	}

	// Final summary
	fmt.Println("----- ORT Recovery Summary -----")
	for _, s := range summary {
		status := "skipped"
		if s.Found && !s.Errored {
			status = fmt.Sprintf("processed (added=%d)", s.Added)
		}
		if s.Errored {
			status = fmt.Sprintf("error: %v", s.Err)
		}
		fmt.Printf("- %s: %s\n", s.Name, status)
	}
}

// ---------------------------
// Main
// ---------------------------
func main() {
	repoFile := flag.String("repoFile", "", "Path to JSON file containing GitHub repos")
	backupDir := flag.String("backup", "recovery_files", "Directory to store backups")
	syftPath := flag.String("syftPath", "syft", "Path to syft binary (default assumes syft is on PATH)")
	verbose := flag.Bool("v", false, "Verbose logging")
	keepTemp := flag.Bool("keep-temp", false, "Keep cloned repo directories for debugging")
	flag.Parse()

	logger, err := utils.NewLogger()
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	if *repoFile == "" {
		logger.Errorf("Please provide -repoFile")
		os.Exit(1)
	}

	// Ensure backup root exists
	if err := os.MkdirAll(*backupDir, 0o755); err != nil {
		logger.Errorf("failed to create backup dir %s: %v", *backupDir, err)
		os.Exit(1)
	}

	// Check syft availability
	if _, err := exec.LookPath(*syftPath); err != nil {
		logger.Errorf("Syft not found at %s (install it or adjust -syftPath)", *syftPath)
		os.Exit(1)
	}

	start := time.Now()

	data, err := os.ReadFile(*repoFile)
	if err != nil {
		logger.Errorf("Failed to read repo JSON file: %v", err)
		os.Exit(1)
	}
	var repoList []RepoEntry
	if err := json.Unmarshal(data, &repoList); err != nil {
		logger.Errorf("Failed to parse JSON: %v", err)
		os.Exit(1)
	}

	tempRoot, err := os.MkdirTemp("", "ort_repos_*")
	if err != nil {
		logger.Errorf("Failed to create temp dir: %v", err)
		os.Exit(1)
	}

	if !*keepTemp {
		defer os.RemoveAll(tempRoot)
	} else {
		logger.Infof("Keeping temp clone directories in: %s", tempRoot)
	}

	for _, r := range repoList {
		branch := r.Branch
		if branch == "" {
			branch = "main"
		}
		clonePath, err := cloneRepo(r.Repo, branch, tempRoot)
		if err != nil {
			logger.Errorf("Failed to clone repo %s: %v", r.Repo, err)
			continue
		}
		if *verbose {
			logger.Infof("Repo cloned to %s", clonePath)
		}

		processProject(logger, *syftPath, clonePath, *backupDir, *verbose)
	}

	elapsed := time.Since(start)
	fmt.Printf("Total elapsed time: %s\n", elapsed)
	logger.Infof("Total elapsed time: %s", elapsed)

	// Explicit close & exit to avoid hanging
	logger.Close()
	os.Exit(0)
}
