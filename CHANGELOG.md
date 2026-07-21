# Changelog

All notable changes to `unslop` will be documented in this file.

## [0.2.0-alpha] - 2026-07-21

### Added
- **Conservative Developer Hygiene Planner**: Read-only plan/report mode as default.
- **Quarantine Isolation Architecture**: Atomic temporary renaming of candidates prior to inspection and deletion.
- **Strict RiskClass Policy Engine**: Candidate action and deletion authority determined strictly by typed `RiskClass` and uninstaller availability.
- **Dual-Timestamp Revalidation**: Independent tracking and pre-action verification of root directory container timestamp vs newest subtree timestamp.
- **Windows Recycle Bin Integration**: Native PowerShell .NET `Microsoft.VisualBasic.FileIO.FileSystem` Recycle Bin support (`unslop_windows.go`).
- **Structured JSON Plan Output**: `-json` and `-plan-out <path>` flags export full plan report with rules, reasons, evidence, sizes, and proposed actions.
- **Non-Zero Exit Status**: CLI returns exit code 1 when deletion/uninstall operations fail or encounter safety aborts.
- **Manifest Migration**: Automatic migration of legacy manifest files to v1 schema definitions.
- **Subtree Protection Guard**: Recursive validation of candidate directories prior to deletion to protect credential/config files.

### Fixed
- Fixed issue where requested scan root directories (e.g. `unslop -path ~/.zig-cache`) were not evaluated as candidates.
- Fixed Windows Recycle Bin removal command by replacing invalid `Remove-Item -Recycle` with native .NET FileSystem API.
- Fixed directory revalidation failures caused by comparing root container timestamps to subtree newest timestamps.
- Single-pass high-performance filesystem traversal eliminating double traversal.
- Structured executable/argument array uninstallation replacing shell string commands.
