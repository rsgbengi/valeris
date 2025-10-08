# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Persistent Configuration
- **TOML-based configuration files** for persistent settings:
  - Supports XDG config directory (`~/.config/valeris/config.toml`)
  - Home directory fallback (`~/.valeris.toml`)
  - Environment variable override (`VALERIS_CONFIG_FILE`)
  - CLI arguments always take precedence over config file
- **Configurable options**:
  - Scan defaults (`default_state`, `only`, `exclude`, `ignore_containers`)
  - Severity defaults (`min_severity`, `fail_on`, `quiet`)
  - Output preferences (`format`, `colors`, `table_width`)
  - Rules directory (`directory`, `auto_download`)
  - Docker settings (`timeout`, `max_parallel`, `host`)
- **New `config` command** to check configuration status:
  - Shows config file locations and parse status
  - Validates TOML syntax
  - Displays loaded sections
  - Provides setup instructions
- Example configuration file: `valeris.toml.example`

#### Severity Filtering and CI/CD Integration
- **Severity filtering** to show only findings at specific risk levels:
  - `--severity` flag for exact severity levels (comma-separated)
  - `--min-severity` flag for minimum severity threshold
  - Supported levels: `informative`, `low`, `medium`, `high`
- **CI/CD integration** with exit code control:
  - `--fail-on` flag to exit with code 1 if findings meet threshold
  - `--quiet` mode for script-friendly output (no stdout, only exit code)
  - Perfect for automated security gates in pipelines
- Added `PartialOrd` and `Ord` to `RiskLevel` enum for severity comparisons
- Complete CI/CD integration guide: `docs/CI-CD-INTEGRATION.md`

#### CLI Improvements
- **Command aliases** for faster workflow:
  - `scan` → `s`
  - `docker-file` → `df`
  - `list-plugins` → `ls`
- **Short flags** for common options:
  - `-c` for `--container`
  - `-t` for `--target`
  - `-f` for `--format`
  - `-o` for `--output`
  - `-p` for `--path` (docker-file)
  - `-r` for `--rules` (docker-file)
- **Container filtering** by name or ID:
  - New `--container` flag to filter scans by container name or ID
  - Supports multiple patterns (comma-separated)
  - Case-insensitive partial matching
  - Works with full container ID, short ID, or container name
- **Comprehensive help** with examples and long descriptions for all commands and options
- **Argument conflicts** to prevent invalid combinations (e.g., `--only` and `--exclude`)

#### Documentation
- Created comprehensive CLI reference guide (`docs/CLI.md`)
- Updated `README.md` with new filtering capabilities and command aliases
- Updated `CLAUDE.md` with detailed CLI usage examples
- Updated `docs/guides/quick-start.md` with new features
- Updated `docs/contributing/CONTRIBUTING.md` with current function signatures

### Changed

#### CLI Architecture
- Changed CLI argument types from `Option<String>` to `Option<Vec<String>>` for comma-separated lists
- Arguments now use `value_delimiter = ','` for better parsing
- Improved argument grouping with logical sections (Target Selection, Detector Filtering, Container Filtering, Severity Filtering, CI/CD Integration, Output Options)
- New `SeverityLevel` enum with `PartialOrd` for comparisons

#### Scanner Improvements
- Updated `scan_docker_with_yaml_detectors()` to accept container name/ID filters
- Updated `get_containers()` with flexible pattern matching for container names and IDs
- Added `parse_container_patterns()` function for normalizing search patterns
- Refactored `parse_comma_separated_set()` to `parse_vec_to_set()` for cleaner API
- New helper functions in `lib.rs`:
  - `apply_config_defaults()` - Merges config file with CLI arguments
  - `filter_by_severity()` - Filters findings by risk level
  - `should_fail()` - Determines exit code based on findings
  - `severity_to_risk()` - Converts SeverityLevel to RiskLevel

#### Configuration System
- Extended `config.rs` module with file-based configuration:
  - New structures: `ScanConfig`, `FileOutputConfig`, `FileRulesConfig`, `FileDockerConfig`, `ConfigFile`
  - `ConfigFile::load()` - Loads and parses TOML files
  - `ConfigFile::load_default()` - Searches standard locations
  - Validates TOML syntax and structure
  - All config structs use `#[serde(default)]` for optional fields

### Tests

- Added 13 new tests for severity filtering and CI/CD features:
  - 5 integration tests for severity/fail-on behavior
  - 6 parser tests for argument validation
  - 2 conflict validation tests
- Added 8 tests for container filtering functionality:
  - 3 integration tests (CLI behavior)
  - 3 parser tests (argument parsing)
  - 2 unit tests (pattern normalization)
- Updated existing tests to work with new `Vec<String>` types
- All 120+ tests passing successfully

### Dependencies

- Added `toml = "0.8"` for TOML configuration file parsing
- Added `derive` feature to `serde` for auto-implementing Serialize/Deserialize

### Fixed

- Fixed test that incorrectly expected `--only` and `--exclude` to work together
- Test now correctly validates that these flags are mutually exclusive
- Fixed CLI argument conflicts with proper `conflicts_with` declarations

## [0.1.0] - Initial Release

### Added
- Runtime container scanning via Docker API
- Dockerfile static analysis
- YAML-based rule engine with JSONPath support
- Multiple output formats (table, JSON, CSV)
- Colored terminal output
- Rule download and management system
- Comprehensive test suite with snapshot testing

---

**Note:** Version 0.1.0 represents the initial alpha release. The project is under active development.
