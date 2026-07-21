# Changelog

All notable changes to `unslop` will be documented in this file.

## [0.2.0-alpha] - 2026-07-21

### Added
- **Conservative Developer Hygiene Planner**: Read-only plan/report mode as default.
- **Risk Classes**: Explicit categorization of candidates into `regenerable`, `package-managed`, `user-data`, and `unknown`.
- **Structured JSON Plan Output**: `-json` and `-plan-out <path>` flags export full plan report with rules, reasons, evidence, sizes, and proposed actions.
- **Sanitized Previews**: Automated redaction of API keys, JWT tokens, and private keys in TUI preview panes.
- **Cross-Platform Compatibility**: Build tags supporting Linux, macOS (Darwin), and Windows (`unslop_posix.go`, `unslop_windows.go`).
- **Version Flag**: Added `unslop -version`.
- **Subtree Protection Guard**: Recursive validation of candidate directories prior to deletion to protect credential/config files.

### Fixed
- Single-pass high-performance filesystem traversal eliminating double traversal.
- Deadlock-free concurrent candidate collector replacing fixed channel buffers.
- Structured executable/argument array uninstallation replacing `sh -c` string commands.
- Cargo, pipx, and npm inventory verification mapping binaries to package registries.
