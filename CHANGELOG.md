# Changelog

All notable changes to SQX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core/Pro separation architecture
- OOB Server trait for Pro integration
- Batch concurrency limit (5) in Core
- Markdown output restricted to Pro
- Comprehensive documentation

### Changed
- AI Cloud providers available in Core (user's own API key)
- Updated feature matrix Core vs Pro

## [0.1.0] - 2024-04-18

### Added
- Initial release
- All SQL injection detection techniques (Error, Boolean, Time, Union, Stacked)
- 69 tamper scripts for WAF evasion
- Interactive SQL and OS shells
- File read/write via SQL injection
- Data extraction and database dumping
- Regex-based web crawler
- Batch scanning (Core: max 5 concurrent)
- AI advisor with Ollama (local) and cloud support
- Session management with authentication
- SOCKS5 and HTTP proxy support
- JSON, SARIF, Text output formats
- SARIF support for GitHub Advanced Security
- Cross-platform support (Linux, macOS, Windows)

### Core Features
- Complete detection engine
- All 69 tamper scripts
- SQL and OS interactive shells
- File system access
- Schema enumeration
- Smart scan with fingerprinting
- CLI interface with all commands

### Pro Features
- Native GUI (egui/eframe)
- Headless browser crawling (Chrome/CDP)
- OOB Server (DNS/HTTP callbacks)
- Second-order SQL injection detection
- Markdown reporting
- Unlimited batch concurrency

---

## Release Checklist Template

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Soon-to-be removed features

### Removed
- Now removed features

### Fixed
- Bug fixes

### Security
- Security fixes
```
