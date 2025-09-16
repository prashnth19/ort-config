# ORT Recovery Tool

A robust dependency recovery and curation tool that reconstructs and repairs dependency manifests for multi-language repositories. It uses [Syft](https://github.com/anchore/syft) for SBOM generation and applies custom curation rules.

## Architecture & Workflow

1. **Input Processing**
   - Reads repository list from [configs/repos.json](configs/repos.json)
   - Validates and processes configuration parameters
   - Sets up backup directories and logging

2. **For Each Repository:**
   - Clones/updates the repository
   - Runs Syft scan to generate SBOM
   - Processes with language-specific handlers
   - Generates recovery files
   - Creates backups of original manifests

3. **Language Processing**
   - Detects applicable language handlers
   - Parses existing manifest files
   - Scans source code for imports/requires
   - Merges declared and detected dependencies
   - Applies curations from master rules

## Supported Languages and Dependency Files

| Language     | Source Extensions                | Dependency / Manifest Files                                                                 |
| ------------ | -------------------------------- | ------------------------------------------------------------------------------------------- |
| **Go**       | `.go`                            | `go.mod`, `go.sum`                                                                          |
| **C / C++**  | `.c`, `.cpp`, `.cc`, `.cxx`, `.h`, `.hpp` | `CMakeLists.txt`, `Makefile`, `conanfile.txt`, `conanfile.py`, `vcpkg.json`, `meson.build`, `BUILD` (Bazel), `configure.ac` |
| **Node.js**  | `.js`, `.mjs`, `.cjs`            | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`                          |
| **PHP**      | `.php`                           | `composer.json`, `composer.lock`                                                            |
| **Python**   | `.py`                            | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, `Pipfile.lock`, `environment.yml` |
| **Java**     | `.java`                          | `pom.xml` (Maven), `build.gradle`, `build.gradle.kts` (Gradle), `settings.gradle`          |
| **.NET**     | `.cs`, `.vb`                     | `.csproj`, `.vbproj`, `packages.config`, `project.json` (legacy), `Directory.Packages.props` |
| **Ruby**     | `.rb`                            | `Gemfile`, `Gemfile.lock`, `.gemspec`                                                       |
| **Rust**     | `.rs`                            | `Cargo.toml`, `Cargo.lock`                                                                  |
| **Scala**    | `.scala`                         | `build.sbt`, `project/*.scala`, `project/*.sbt`                                             |
| **Kotlin**   | `.kt`, `.kts`                    | `build.gradle`, `build.gradle.kts`, `pom.xml` (if Maven)                                   |


## Prerequisites

1. **System Requirements**
   - Go 1.20 or higher
   - Git client
   - [Syft](https://github.com/anchore/syft) v1.32.0+ installed and in PATH

2. **Configuration Files**
   - `configs/repos.json` - Repository list
   - `configs/master_curations.yml` - Dependency curations

## Installation

```sh
# Clone repository
git clone <repo-url>
cd ort-recovery

# Install dependencies
go mod download

# Build
go build -o ort-recovery
```

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

### 3. Run Recovery

```sh
./ort-recovery -repoFile configs/repos.json -backup recovery_files -v
```

Options:
- `-repoFile`: Path to repos.json
- `-backup`: Output directory for recovery files
- `-syftPath`: Custom path to Syft binary
- `-v`: Verbose logging
- `-keep-temp`: Keep temporary files

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
          
      - name: Run Recovery
        run: |
          go build
          ./ort-recovery -repoFile configs/repos.json -backup recovery_files -v
          
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
                    go build -o ort-recovery
                '''
            }
        }
        
        stage('Run Recovery') {
            steps {
                sh './ort-recovery -repoFile configs/repos.json -backup recovery_files -v'
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

## Supported Languages & Manifest Types

- Java: `pom.xml`, `build.gradle`
- Python: `requirements.txt`, `setup.py`, `Pipfile`, `pyproject.toml`
- Node.js: `package.json`
- Go: `go.mod`
- Rust: `Cargo.toml`
- .NET: `.csproj`, `packages.config`
- Ruby: `Gemfile`, `.gemspec`
- PHP: `composer.json`
- C++: `vcpkg.json`, `conanfile.txt`, `CMakeLists.txt`
- Swift: `Package.swift`

## Architecture Notes

- **Handlers**: Language-specific logic in `handlers/` directory
- **Utils**: Common utilities in `utils/` directory
- **Backup**: Original files preserved in backup directory
- **Logging**: Detailed logs for debugging and auditing

## License

Properietary