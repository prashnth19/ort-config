# ORT Config

A robust dependency recovery and curation tool that reconstructs and repairs dependency manifests for multi-language repositories.
It bridges the gap between **Syft** (SBOM generator) and **OSS Review Toolkit (ORT)** by cleaning repositories and ensuring manifests are complete before ORT analysis.

⚡ **Why we built this:**

* ORT by default **only reads dependency files** (`go.mod`, `requirements.txt`, `pom.xml`, etc.) but does **not scan raw source files** for missing imports.
* In many of our repos, these files are incomplete, missing, or corrupted. This causes ORT to misreport “no dependencies found.”
* Syft scans at the package level but doesn’t generate missing manifests.
* This tool **fills that gap** by scanning the code, detecting imports, auto-generating/repairing manifests, and passing clean inputs to ORT.

---

## Architecture & Workflow

1. **Input Processing**

   * Reads repository list from [configs/repos.json](configs/repos.json)
   * Validates and processes configuration parameters
   * Sets up backup directories and logging

2. **For Each Repository**

   * Clones/updates the repository
   * Runs Syft scan to generate SBOM
   * Passes repo to language-specific handlers
   * Repairs or creates manifest files (e.g., `go.mod`, `requirements.txt`)
   * Backs up originals for audit

3. **Language Handlers**

   * **Detect** source language via file extensions
   * **Parse** existing manifest files
   * **Scan** source code for imports/requires
   * **Merge** declared + detected dependencies
   * **Apply** curations from master rules

---

## Major Features We Implemented

* ✅ **Go Handler**

  * Auto-generates `go.mod` if missing using `go mod init`
  * Scans `.go` files for imports
  * Runs `go mod tidy` at the right stage
  * Verbose logs added for each step to debug failures

* ✅ **Python Handler**

  * Supports `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile`
  * Scans `.py` imports and adds missing packages

* ✅ **Swift Handler**

  * Detects `Package.swift`, scans `.swift` files
  * Adds missing dependencies

* ✅ **C++ Handler**

  * Handles multiple build systems (`CMake`, `Meson`, `Conan`, `vcpkg`, `Bazel`)

* ✅ **Logging Fixes**

  * Standardized `utils.AppendLog` calls
  * Added fine-grained logs in every step to trace dependency detection

* ✅ **Repo Pre-cleanup**

  * Ensures manifests exist and are valid *before* ORT runs
  * Prevents ORT errors and avoids “no dependencies found” reports

---

## Supported Languages and Dependency Files

| Language    | Source Extensions                         | Dependency / Manifest Files                                                                                                 |
| ----------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **Go**      | `.go`                                     | `go.mod`, `go.sum`                                                                                                          |
| **C / C++** | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp` | `CMakeLists.txt`, `Makefile`, `conanfile.txt`, `conanfile.py`, `vcpkg.json`, `meson.build`, `BUILD` (Bazel), `configure.ac` |
| **Node.js** | `.js`, `.mjs`, `.cjs`                     | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`                                                          |
| **PHP**     | `.php`                                    | `composer.json`, `composer.lock`                                                                                            |
| **Python**  | `.py`                                     | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `Pipfile.lock`, `environment.yml`                              |
| **Java**    | `.java`                                   | `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`                                                            |
| **.NET**    | `.cs`, `.vb`                              | `.csproj`, `.vbproj`, `packages.config`, `project.json`, `Directory.Packages.props`                                         |
| **Ruby**    | `.rb`                                     | `Gemfile`, `Gemfile.lock`, `.gemspec`                                                                                       |
| **Rust**    | `.rs`                                     | `Cargo.toml`, `Cargo.lock`                                                                                                  |
| **Scala**   | `.scala`                                  | `build.sbt`, `project/*.scala`, `project/*.sbt`                                                                             |
| **Kotlin**  | `.kt`, `.kts`                             | `build.gradle`, `build.gradle.kts`, `pom.xml`                                                                               |

---

## Prerequisites

1. **System Requirements**

   * Go 1.20+
   * Git client
   * [Syft](https://github.com/anchore/syft) v1.32.0+

2. **Configuration Files**

   * `configs/repos.json` – Repository list
   * `configs/master_curations.yml` – Dependency curations

---

## Installation

```sh
git clone <repo-url>
cd ort-config
go mod download
go build -o ort-config
```

---

## Usage

### 1. Configure Repository List

Edit `configs/repos.json`:

```json
[
  {
    "repo": "https://github.com/org/repo.git",
    "branch": "main",
    "product": "product-name"
  }
]
```

### 2. Configure Curations (Optional)

Edit `configs/master_curations.yml`:

```yaml
- key: "group:artifact"
  version: "2.0.0"
  scope: "compile"
```
Options:

* `-repoFile` → Path to repos.json
* `-backup` → Output directory for recovery files
* `-syftPath` → Custom Syft binary path
* `-v` → Verbose logging
* `-keep-temp` → Keep temporary files

---

## CI/CD Integration

Supports **GitHub Actions** and **Jenkins pipelines** (examples included).

## CI/CD Integration

### GitHub Actions Example

```yaml
name: ORT Recovery
on: [push]

jobs:
  recover:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.20'
          
      - name: Install Syft
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
          
      - name: ORT Config
        run: |
          go build
          ./ort-config -repoFile configs/repos.json -backup recovery_files -v
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: recovery-files
          path: recovery_files/
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    tools {
        go 'go-1.20'
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
                    go build -o ort-config
                '''
            }
        }
        
        stage('Run Recovery') {
            steps {
                sh './ort-config -repoFile configs/repos.json -backup recovery_files -v'
            }
        }
        
        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'recovery_files/**/*'
            }
        }
    }
}
```
---

## Why This Script Matters

* ORT alone fails when manifests are missing → results in **false negatives**.
* Syft detects packages but doesn’t fix manifests.
* This tool **repairs repos before ORT runs**, ensuring:

  * More accurate dependency detection
  * Cleaner SBOM generation
  * Fewer ORT pipeline failures
  * Consistent results across multi-language projects

---

## License

Proprietary

---

