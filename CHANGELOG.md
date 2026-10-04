# Changelog

All notable changes to `unslop` will be documented in this file.

## Unreleased

### Added
- Automatically discover repositories, group their registered worktrees, and show outstanding feature commits in the Repos tab (`r`); return to Files with `f`.
- Reuse Git ancestry and patch comparisons to distinguish integrated work, successor branches, and changes requiring review.
- Report obsolete linked directories only after checking retained history, local changes, ignored files, and locks.

### Fixed
- Skip generated `.giga` repositories during discovery; open Repos immediately with live results and an adaptive progress footer.
- Route macOS cleanup through native Trash and replace the Linux executable with a portable source launcher.
- Match path rules against absolute scan paths; anchor default user stores to home.
- Report filesystem access failures and stop cleanup after an incomplete scan.
- Require `fzf` for cleanup and enforce `-apply-data` for history deletion.
- Keep standalone binaries report-only; add Xcode and Homebrew cache discovery.
- Stop treating arbitrary cache directories, including model stores, as disposable temporary data.
- Add opt-in Antigravity artifact/conversation stores and individual pi sessions while preserving credentials and configuration.
- Use Giga's Go preset instead of Linux checkout paths and fabricated analyzer reports.

Cause: Linux assumptions and blanket credential guards bypassed native Trash and session discovery; deletion did not enforce the second data opt-in.
Missed signal: Platform command mocks and name-only fixtures did not exercise absolute paths, complete cleanup, or session stores.
Prevention: Regression tests cover native Trash routing, absolute path matching, permission failures, session discovery, and both data opt-ins.

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
