# Contributing to Valeris

Thank you for your interest in contributing to Valeris! This document provides guidelines and instructions for contributing.

## 🎯 How to Contribute

### Types of Contributions

1. **Bug Reports** - Report issues you encounter
2. **Feature Requests** - Suggest new functionality
3. **Security Rules** - Add new detection rules
4. **Documentation** - Improve or add documentation
5. **Code Improvements** - Refactoring, performance, tests

## 🐛 Reporting Bugs

### Before Submitting

- Check if the bug has already been reported
- Collect as much information as possible
- Try to reproduce the issue consistently

### Bug Report Template

```markdown
**Description:**
A clear description of what the bug is.

**To Reproduce:**
Steps to reproduce the behavior:
1. Run command '...'
2. With these options '...'
3. See error

**Expected Behavior:**
What you expected to happen.

**Actual Behavior:**
What actually happened.

**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Rust version: [e.g., 1.71.0]
- Docker version: [e.g., 24.0.5]
- Valeris version: [e.g., 0.1.0]

**Additional Context:**
Add any other context, logs, or screenshots.
```

## 💡 Feature Requests

### Feature Request Template

```markdown
**Problem Statement:**
Describe the problem this feature would solve.

**Proposed Solution:**
Describe how you envision the feature working.

**Alternatives Considered:**
Other approaches you've thought about.

**Additional Context:**
Any other relevant information.
```

## 🛡️ Adding Security Rules

### Dockerfile Rules

1. **Create YAML file** in `rules/dockerfile/`

```yaml
version: 1
rules:
  - id: DF999
    name: "Rule Name"
    scope: instruction  # instruction | stage | file
    kind: RUN          # For instruction scope
    match:
      field: command
      regex: "dangerous-pattern"
    severity: high     # critical | high | medium | low | info
    message: "Clear description of the issue"
    remediation: "How to fix this issue"
    tags: [security, best-practices]
```

2. **Test your rule**

```bash
# Create test Dockerfile
cat > /tmp/test.dockerfile << 'EOF'
FROM ubuntu:latest
RUN dangerous-command
EOF

# Test the rule
cargo run -- docker-file --path /tmp/test.dockerfile --rules ./rules/dockerfile
```

3. **Add test case**

Add to `tests/dockerfile_integration_tests.rs`:
```rust
#[test]
fn test_df999_dangerous_command() {
    // Test implementation
}
```

### Runtime Rules

1. **Create YAML file** in `rules/runtime/docker/`

```yaml
id: new_detector
name: "Detector Name"
target: docker_runtime
severity: HIGH
description: What this detector checks
match:
  jsonpath: "$.HostConfig.SomeField"
  regex: "pattern"
include_match_in_description: true
message: "Issue description"
fix: |
  How to remediate this issue
```

2. **Test with live container**

```bash
# Create test container
docker run -d --name test-container \
  --some-flag \
  nginx

# Test the rule
cargo run -- scan --only new_detector

# Cleanup
docker rm -f test-container
```

3. **Add integration test**

Add expected finding to `tests/data/` and update snapshots:
```bash
cargo insta review
```

## 💻 Code Contributions

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/valeris.git
cd valeris

# Create feature branch
git checkout -b feature/my-contribution

# Build and test
cargo build
cargo test
cargo clippy -- -D warnings
```

### Code Style

1. **Rust Style Guide**
   - Follow official Rust style
   - Run `rustfmt` before committing
   - Keep lines under 100 characters

2. **Naming Conventions**
   - `snake_case` for functions and variables
   - `PascalCase` for types
   - `SCREAMING_SNAKE_CASE` for constants

3. **Documentation**
   - Add doc comments (`///`) to public functions
   - Include examples in doc comments
   - Document parameters and return values

```rust
/// Scans Docker containers using YAML-based detection rules.
///
/// # Arguments
///
/// * `rules_dir` - Path to directory containing YAML rule files
/// * `state` - Optional container state filter (e.g., "running")
///
/// # Returns
///
/// `Result<Vec<ContainerResult>>` containing findings for each container
///
/// # Errors
///
/// Returns an error if:
/// * Rules cannot be loaded
/// * Docker daemon is unreachable
///
/// # Example
///
/// ```rust
/// let results = scan_docker_with_yaml_detectors(
///     PathBuf::from("./rules"),
///     Some("running".to_string())
/// ).await?;
/// ```
pub async fn scan_docker_with_yaml_detectors(
    rules_dir: PathBuf,
    state: Option<String>,
) -> Result<Vec<ContainerResult>> {
    // Implementation
}
```

### Testing Requirements

1. **Unit Tests** - Test individual functions

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_comma_separated_set() {
        let input = Some("foo,bar,baz".to_string());
        let result = parse_comma_separated_set(&input).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains("foo"));
    }
}
```

2. **Integration Tests** - Test full workflows

```rust
#[test]
fn test_dockerfile_scan_detects_root_user() {
    let output = Command::cargo_bin("valeris")
        .unwrap()
        .args(&["docker-file", "--path", "examples/bad-dockerfile"])
        .output()
        .unwrap();

    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("Container runs as root"));
}
```

3. **Snapshot Tests** - Validate expected output

```rust
#[test]
fn test_rule_output_snapshot() {
    let findings = scan_with_rules(&test_data);
    insta::assert_json_snapshot!(findings);
}
```

### Commit Guidelines

1. **Commit Message Format**

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `style` - Code style (formatting)
- `refactor` - Code refactoring
- `test` - Adding tests
- `chore` - Maintenance tasks

**Examples:**
```
feat(rules): add Dockerfile rule for sudo detection

Adds DF601 to detect sudo usage in RUN instructions which is
unnecessary and potentially insecure in Docker contexts.

Closes #123
```

```
fix(scanner): handle containers without inspect data

Some containers may not have complete inspect data.
Added graceful error handling to prevent panics.
```

2. **Keep commits atomic**
   - One logical change per commit
   - Can be cherry-picked independently
   - Includes relevant tests

3. **Sign your commits** (optional but recommended)

```bash
git commit -S -m "feat: add new feature"
```

### Pull Request Process

1. **Before Submitting**

```bash
# Update from main
git fetch origin
git rebase origin/main

# Run full test suite
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# Update documentation if needed
```

2. **PR Description Template**

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] All tests passing
- [ ] No Clippy warnings

## Related Issues
Closes #123
Fixes #456
```

3. **Review Process**
   - Maintainer will review within 48 hours
   - Address review comments
   - Keep PR scope focused
   - Squash commits if requested

## 📝 Documentation Contributions

### Types of Documentation

1. **Code Documentation** - Doc comments in source
2. **User Guides** - How-to guides in `docs/guides/`
3. **Architecture Docs** - Design docs in `docs/architecture/`
4. **API Reference** - Generated from doc comments

### Documentation Style

- Use clear, concise language
- Include code examples
- Add diagrams where helpful
- Keep audience in mind (beginner vs advanced)

### Building Docs

```bash
# Generate API docs
cargo doc --open

# Preview mdBook (if added)
mdbook serve docs/
```

## 🧪 Testing

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test '*'

# Update snapshots
cargo insta review
```

### Writing Good Tests

1. **Name tests clearly**
```rust
#[test]
fn parse_comma_separated_handles_whitespace() { ... }
```

2. **Test edge cases**
```rust
#[test]
fn handles_empty_input() { ... }

#[test]
fn handles_malformed_json() { ... }
```

3. **Use descriptive assertions**
```rust
assert_eq!(
    result.len(), 3,
    "Expected 3 findings but got {}",
    result.len()
);
```

## 🔒 Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email security reports to: security@example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Best Practices

1. **Input Validation** - Validate all user input
2. **Error Handling** - Don't leak sensitive info in errors
3. **Dependencies** - Keep dependencies updated
4. **Code Review** - Security-sensitive code needs review

## 📋 Checklist for Contributors

Before submitting:

- [ ] Code follows project style
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No breaking changes (or documented if needed)
- [ ] Clippy passes with no warnings
- [ ] `cargo fmt` applied
- [ ] PR description complete

## 🎓 Learning Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Docker API Docs](https://docs.docker.com/engine/api/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [Valeris Blog Series](https://www.kayssel.com/series/docker-security/)

## 📞 Getting Help

- 💬 [Discussions](https://github.com/rsgbengi/valeris/discussions)
- 📖 [Documentation](../README.md)
- 🐛 [Issue Tracker](https://github.com/rsgbengi/valeris/issues)

## 🙏 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Given credit in commit messages

Thank you for contributing to Valeris! 🎉
