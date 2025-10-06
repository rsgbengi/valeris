# Architecture Overview

Valeris is designed as a modular security scanner with a declarative rule engine at its core.

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Layer                            │
│  (clap - Argument parsing, command routing)              │
└───────────────────┬─────────────────────────────────────┘
                    │
        ┌───────────┴────────────┐
        │                        │
        ▼                        ▼
┌───────────────┐        ┌──────────────────┐
│   Dockerfile  │        │   Runtime        │
│   Scanner     │        │   Scanner        │
└───────┬───────┘        └────────┬─────────┘
        │                         │
        │    ┌────────────────────┘
        │    │
        ▼    ▼
┌─────────────────────────────┐
│    YAML Rule Engine         │
│  (JSONPath + Regex/Equals)  │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────┐
│    Output Layer             │
│  • Printer (Table)          │
│  • Exporters (JSON/CSV)     │
└─────────────────────────────┘
```

## 📦 Core Components

### 1. CLI Layer (`src/cli.rs`)

Entry point for all user interactions. Uses **clap** for argument parsing.

**Commands:**
- `scan` - Runtime container scanning
- `docker-file` - Dockerfile static analysis
- `list-plugins` - Show available detectors

**Key Responsibilities:**
- Parse command-line arguments
- Validate user input
- Route to appropriate scanner
- Handle output formatting preferences

```rust
pub enum Commands {
    Scan {
        target: Option<String>,
        only: Option<String>,
        exclude: Option<String>,
        state: Option<String>,
        format: OutputFormat,
        output: Option<String>,
    },
    DockerFile {
        path: PathBuf,
        rules: PathBuf,
        format: OutputFormat,
        output: Option<String>,
    },
    ListPlugins {
        target: Option<String>,
    },
}
```

### 2. Configuration (`src/config.rs`)

Centralized configuration management with environment variable support.

**Configuration Modules:**
- `RulesConfig` - Rule directory location, auto-download settings
- `DockerConfig` - Docker client timeouts, parallel scan limits
- `OutputConfig` - Terminal colors, table width, verbosity

**Environment Variables:**
- `VALERIS_RULES_DIR` - Override default rules location
- `RUST_LOG` - Control logging level (debug, info, warn, error)

```rust
pub struct AppConfig {
    pub rules: RulesConfig,
    pub docker: DockerConfig,
    pub output: OutputConfig,
}
```

### 3. Rule Engine (`src/detectors/runtime/yaml_rules.rs`)

Heart of Valeris - processes YAML rules and matches them against data.

**Key Features:**
- JSONPath expressions for data extraction
- Regex and exact string matching
- Multi-part matching with cartesian products
- Severity-based risk classification

**Rule Structure:**
```yaml
id: rule_id
name: "Human Readable Name"
target: docker_runtime
severity: HIGH
match:
  jsonpath: "$.HostConfig.Privileged"
  equals: "true"
message: "Container is running in privileged mode"
```

**Matcher Types:**
1. **JSONPath only** - Extract and match presence
2. **JSONPath + Equals** - Exact value matching
3. **JSONPath + Regex** - Pattern matching
4. **Parts** - Combine multiple fields with separator

### 4. Scanners

#### Runtime Scanner (`src/detectors/runtime/scanner.rs`)

Connects to Docker daemon via **Bollard** (async Docker client).

**Flow:**
1. Load YAML rules from directory
2. Connect to Docker socket
3. List containers (with optional state filter)
4. Inspect each container → Convert to JSON
5. Apply YAML rules to JSON
6. Collect and filter findings
7. Return structured results

**Data Flow:**
```rust
Docker API → ContainerInspectResponse → JSON
          ↓
    YAML Rule Engine
          ↓
    Vec<Finding>
```

#### Dockerfile Scanner (`src/detectors/dockerfile/scanner.rs`)

Uses **dockerfile-parser** crate to parse Dockerfile AST.

**Scopes:**
- **Instruction** - Matches individual instructions (FROM, RUN, USER)
- **Stage** - Matches entire build stages
- **File** - File-level checks (.dockerignore)

**Flow:**
1. Parse Dockerfile → AST
2. Extract instructions/stages
3. Convert to searchable map format
4. Apply YAML rules
5. Collect findings with line numbers

### 5. Output Layer (`src/output/`)

Unified output handling for all scan types.

#### Printer (`src/output/printer.rs`)

Terminal output with **console** and **comfy-table** crates.

**Features:**
- Colored severity indicators
- Unicode box-drawing tables
- Contextual headers (Container vs Dockerfile)
- Summary statistics

```rust
pub enum ScanContext<'a> {
    Container(&'a ContainerInspectResponse),
    Dockerfile(&'a PathBuf),
}

pub fn print_scan_report(context: ScanContext, findings: &[Finding])
```

#### Exporters (`src/output/exporters.rs`)

JSON and CSV export for CI/CD integration.

**Export Formats:**
- **JSON** - Structured data with metadata
- **CSV** - Flat format for spreadsheet analysis

```rust
pub enum ScanSource<'a> {
    Containers(&'a [ContainerResult]),
    Dockerfile { path: &'a Path, findings: &'a [Finding] },
}
```

### 6. Rules Management (`src/rules.rs`)

Automatic rule download and installation.

**Default Locations:**
- `$XDG_DATA_HOME/valeris/detectors` (Linux)
- `$HOME/.local/share/valeris/detectors` (fallback)
- `$VALERIS_RULES_DIR` (custom override)

**First-Run Behavior:**
1. Check if rules exist
2. If not, download from GitHub releases
3. Extract to data directory
4. Load rules on demand

## 🔄 Execution Flow

### Runtime Scan Flow

```
1. User runs: valeris scan --state running

2. CLI parses arguments → Commands::Scan

3. ensure_rules()
   ├─> Check rules directory
   └─> Download if missing

4. YamlRuleEngine::from_dir(rules_dir)
   └─> Load all *.yaml files

5. Docker::connect()
   └─> List containers with state filter

6. For each container:
   ├─> Inspect container
   ├─> Convert to JSON
   ├─> YamlRuleEngine::scan_value()
   └─> Collect findings

7. Filter findings (--only, --exclude)

8. Output:
   ├─> print_scan_report() (table)
   ├─> export_json() (--format json)
   └─> export_csv() (--format csv)
```

### Dockerfile Scan Flow

```
1. User runs: valeris docker-file --path ./Dockerfile

2. CLI parses arguments → Commands::DockerFile

3. dockerfile_parser::parse_file()
   └─> AST with stages/instructions

4. Load YAML rules from --rules directory

5. For each instruction:
   ├─> Extract fields (kind, user, port, etc.)
   ├─> Convert to map
   └─> Match against rules

6. For each stage:
   └─> Apply stage-level rules

7. File-level checks
   └─> .dockerignore, COPY . patterns

8. Output findings with line numbers
```

## 🧩 Key Design Patterns

### 1. **Declarative Rules**
Rules are data, not code. Add detectors without recompiling.

### 2. **Unified Output**
Single printer/exporter interface for all scan types.

### 3. **Async by Default**
Docker API calls use Tokio for concurrency.

### 4. **Error Context**
All errors include context via `anyhow::Context`.

### 5. **Type Safety**
Strong typing for `Finding`, `RiskLevel`, `ScanContext`.

## 📊 Data Models

### Finding
```rust
pub struct Finding {
    pub kind: String,           // Rule ID
    pub description: String,     // User-facing message
    pub risk: RiskLevel,        // Severity
    pub line: Option<usize>,    // Line number (Dockerfile only)
}
```

### RiskLevel
```rust
pub enum RiskLevel {
    High,         // CRITICAL/HIGH
    Medium,       // MEDIUM
    Low,          // LOW
    Informative,  // INFO
}
```

### ContainerResult
```rust
pub struct ContainerResult {
    pub container: ContainerInspectResponse,  // Docker API response
    pub findings: Vec<Finding>,               // Detected issues
}
```

## 🔌 Extensibility Points

### Adding New Detectors

**Runtime Rules:**
1. Create YAML file in `rules/runtime/docker/`
2. Define JSONPath expression
3. Set severity and message
4. Rules auto-load on next scan

**Dockerfile Rules:**
1. Create YAML file in `rules/dockerfile/`
2. Specify scope (instruction/stage/file)
3. Define match criteria
4. Rules auto-load on next scan

### Adding New Output Formats

Implement in `src/output/exporters.rs`:
```rust
pub enum OutputFormat {
    Table,
    Json,
    Csv,
    // Add: Html, Sarif, etc.
}
```

## 🧪 Testing Strategy

### Unit Tests
- Isolated component testing
- Mock Docker responses
- Rule matching logic

### Integration Tests
- End-to-end command execution
- Example Dockerfile scanning
- Container inspection flows

### Snapshot Tests (insta)
- YAML rule catalog consistency
- Output format validation
- Expected findings verification

## 📚 Dependencies

### Core
- **clap** - CLI argument parsing
- **tokio** - Async runtime
- **bollard** - Docker API client
- **serde** - Serialization

### Parsing
- **dockerfile-parser** - Dockerfile AST
- **jsonpath_lib** - JSONPath queries
- **serde_yml** - YAML parsing

### Output
- **console** - Terminal styling
- **comfy-table** - Table rendering

### Testing
- **insta** - Snapshot testing
- **tempfile** - Temporary test files
- **serial_test** - Sequential tests

## 🔍 Next Steps

- [Rule Engine Deep Dive](rule-engine.md)
- [Custom Rules Guide](custom-rules.md)
- [Testing Architecture](../contributing/testing.md)
