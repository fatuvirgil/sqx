# Contributing to SQX

Thank you for your interest in contributing to SQX! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and constructive
- Focus on technical merit
- Welcome newcomers
- Respect security considerations (no vulnerability disclosure in public issues)

## Getting Started

### Prerequisites

- **Rust** 1.75 or higher
- **Git** for version control
- **Cargo** (comes with Rust)

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/sqx.git
cd sqx

# Build the project
cargo build

# Run tests
cargo test

# Build release version
cargo build --release
```

### Project Structure

```
sqx/
├── sqx-core/          # Core library (open source)
├── sqx-cli/           # CLI binary (open source)
├── sqx-pro/           # Commercial features (separate licensing)
├── DOCS/              # Documentation
├── tests/             # Integration tests
└── Cargo.toml         # Workspace configuration
```

## Contribution Areas

### 1. Bug Fixes

Found a bug? Please report it!

**Before reporting:**
- Check existing issues
- Try latest main branch
- Gather minimal reproduction steps

**Bug report template:**
```markdown
**Description:**
Clear description of the bug

**Steps to Reproduce:**
1. Run `sqx ...`
2. Observe ...

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**
- OS: (e.g., Ubuntu 22.04)
- Rust version: (e.g., 1.75.0)
- SQX version: (e.g., 0.1.0)

**Logs:**
```
RUST_LOG=sqx=trace sqx ...
```
```

### 2. New Tamper Scripts

Adding new WAF evasion techniques:

1. Create file in `sqx-core/src/sqx/evasion/tamper/`
2. Implement `Tamper` trait
3. Register in `evasion/tamper/mod.rs`
4. Add tests

Example:
```rust
use crate::sqx::evasion::Tamper;

pub struct MyTamper;

impl Tamper for MyTamper {
    fn name(&self) -> &'static str {
        "my_tamper"
    }
    
    fn apply(&self, payload: &str) -> String {
        // Your transformation logic
        payload.replace(" ", "/**/")
    }
}
```

### 3. Detection Technique Improvements

Improving existing detection methods:

- Better payload selection
- Reduced false positives
- Faster detection
- New DBMS support

### 4. Documentation

- Fix typos
- Clarify explanations
- Add examples
- Translate (future)

### 5. Tests

- Unit tests for new functions
- Integration tests for features
- Benchmark tests for performance

## Development Workflow

### 1. Fork and Branch

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/sqx.git
git checkout -b feature/my-feature
```

### 2. Make Changes

- Write code following style guidelines
- Add tests for new functionality
- Update documentation

### 3. Test

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=sqx=debug cargo test -- --nocapture

# Check formatting
cargo fmt -- --check

# Run clippy
cargo clippy -- -D warnings
```

### 4. Commit

Follow conventional commits:

```bash
# Format:
# type(scope): description

# Examples:
git commit -m "feat(tamper): add new mysql comment bypass"
git commit -m "fix(detector): correct boolean calibration"
git commit -m "docs(readme): clarify installation steps"
git commit -m "test(shell): add os-shell integration tests"
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, no code change
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

### 5. Push and PR

```bash
git push origin feature/my-feature
```

Create Pull Request on GitHub with:
- Clear title and description
- Reference to related issues
- Test results
- Documentation updates

## Code Style

### Rust Style

Follow standard Rust conventions:

```rust
// Use rustfmt
cargo fmt

// Follow clippy suggestions
cargo clippy
```

Key points:
- Max 100 characters per line
- Descriptive variable names
- Comments for complex logic
- Doc comments (`///`) for public APIs

### Documentation

```rust
/// Brief description of the function.
///
/// More detailed explanation if needed.
///
/// # Arguments
///
/// * `url` - The target URL to scan
/// * `param` - The parameter name to test
///
/// # Returns
///
/// Returns `Ok(Vec<SqliTestResult>)` on success
///
/// # Errors
///
/// Returns `Err` if the URL is invalid
///
/// # Examples
///
/// ```
/// let detector = SqliDetector::new()?;
/// let results = detector.test_url("http://example.com/?id=1").await?;
/// ```
pub async fn test_url(&self, url: &str) -> Result<Vec<SqliTestResult>> {
    // Implementation
}
```

### Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        let result = my_function("input");
        assert_eq!(result, "expected");
    }

    #[tokio::test]
    async fn test_async_function() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

## Testing Guidelines

### Unit Tests

Test individual functions in isolation:

```rust
// In your_module.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tamper_apply() {
        let tamper = SpaceToComment;
        assert_eq!(
            tamper.apply("SELECT * FROM users"),
            "SELECT/**//*FROM/**/users"
        );
    }
}
```

### Integration Tests

Test full workflows in `tests/` directory:

```rust
// tests/integration_test.rs
use sqx_core::sqx::SqliDetector;

#[tokio::test]
async fn test_full_scan() {
    let detector = SqliDetector::new().unwrap();
    // Test against local test server
}
```

### Test Data

Use `tests/fixtures/` for test data:
- Sample HTTP responses
- Test payloads
- Expected outputs

## Performance Considerations

When contributing, consider:

1. **Async/Await**: Use non-blocking operations
2. **Memory**: Avoid unnecessary allocations
3. **Concurrency**: Respect rate limits
4. **Timeouts**: Always set reasonable timeouts

```rust
// Good: Bounded channels, timeouts
let (tx, rx) = tokio::sync::mpsc::channel(100);
tokio::time::timeout(Duration::from_secs(30), operation).await

// Avoid: Unbounded growth
let mut vec = Vec::new();
// Without limiting loop iterations
```

## Security Guidelines

### Responsible Disclosure

**Never** report security vulnerabilities in public:

1. Email security concerns to: security@sqx.io
2. Allow time for fix before disclosure
3. Coordinate disclosure timeline

### Secure Coding

- Validate all inputs
- Use parameterized queries (ironically, in our own code)
- Don't log sensitive data (cookies, passwords)
- Use constant-time comparison where relevant

## Feature Request Process

1. **Check existing issues** for similar requests
2. **Open an issue** describing:
   - Use case
   - Proposed solution
   - Alternatives considered
3. **Discussion** with maintainers
4. **Implementation** (if approved)

## Core vs Pro

### What Goes in Core

- Detection techniques
- Basic exploitation
- Standard output formats
- CLI interface

### What Goes in Pro

- GUI
- Team features
- Advanced reporting
- Commercial integrations

**When in doubt**, open an issue to discuss.

## Review Process

1. **Automated checks** must pass:
   - Tests
   - Clippy
   - Formatting

2. **Maintainer review**:
   - Code quality
   - Architecture fit
   - Security considerations

3. **Approval and merge**:
   - Squash merge for clean history
   - Maintainer merges

## Release Process

1. Version bump in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Tag release: `git tag v0.x.x`
4. Push tags: `git push --tags`
5. CI builds releases
6. GitHub release notes

## Getting Help

- **Discord**: [Join our community](https://discord.gg/sqx)
- **GitHub Discussions**: For questions
- **GitHub Issues**: For bugs and features
- **Email**: contact@sqx.io

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

Thank you for contributing to SQX!

---

**License:** By contributing, you agree that your contributions will be licensed under the MIT/Apache-2.0 dual license.
