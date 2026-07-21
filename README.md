# unslop (Experimental Read-Only Alpha v0.2.0)

> **What**: `unslop` is an experimental, conservative developer-workstation hygiene planner that analyzes build caches, toolchain artifacts, AI agent logs, and model weights across your system.
> **Why**: Use it to inspect, explain, and plan disk reclamation across developer tools and AI workflows with explicit risk classification, structured package provenance, JSON plan export, and multi-layered safety guards.

> [!IMPORTANT]
> `unslop` is currently in **Experimental Read-Only Alpha**. It defaults to plan and report mode. Deletion mode requires explicit `--apply` opt-in.

---

## Installation

Install via standard Go tooling:

```bash
go install github.com/yahn/unslop@latest
```

### Dependencies
- **Go**: Version 1.22+
- **FZF (Optional)**: `fzf` for interactive terminal UI filtering. If `fzf` is absent, `unslop` outputs a clean, structured text plan report.

---

## Risk Classes

`unslop` categorizes all candidates into explicit risk levels:

1. **`regenerable`** *(Safe)*: Build artifacts and compiler outputs (`.zig-cache`, `target/`, `.gradle`, `node_modules/.cache`) that can be transparently recreated by build tools.
2. **`package-managed`** *(Toolchain)*: Binaries mapped directly to native package inventories (`cargo`, `pipx`, `npm`, `swiftly`, `sdkman`, `dotnet`, `composer`) that execute native package uninstallation.
3. **`user-data`** *(Review-Only / Opt-In)*: Local LLM model weights, AI agent conversation histories, logs, and large JSON dumps. **Excluded by default unless `--include-data` is specified.**
4. **`unknown`** *(Report-Only / Custom)*: Custom user-defined patterns (`+pattern`) and unverified binary paths. **Never automatically deleted in `-apply` mode.**

---

## Usage & Commands

```bash
# Run in default Read-Only Plan Mode (scans safe regenerable caches)
unslop

# Export structured JSON plan report
unslop -json -plan-out plan.json

# Include user data, AI agent sessions, and LLM weights for review
unslop -include-data

# Custom age window (e.g. 14 days) and minimum size (e.g. 10 MB)
unslop -days 14 -min-size-mb 10

# Move candidates to System Trash (Trash mode is enabled by default)
unslop -apply

# Perform permanent deletion without Trash (bypasses system Trash)
unslop -apply -force-permanent
```

---

## Structured JSON Plan Output (`-json` / `-plan-out`)

```json
{
  "version": "0.2.0-alpha",
  "scanned_at": "2026-07-21T14:35:00Z",
  "disk_usage": {
    "total_bytes": 1073741824000,
    "used_bytes": 429496729600,
    "free_bytes": 644245094400
  },
  "total_candidates": 1,
  "total_size_bytes": 125829120,
  "candidates": [
    {
      "id": 1,
      "path": "/home/user/.cache/zig",
      "size_bytes": 125829120,
      "age_days": 14.2,
      "category": "Cache Dir",
      "rule_id": "zig_cache",
      "risk_class": "regenerable",
      "reason": "Stale build cache unused for 14.2 days",
      "evidence": "Last modified 14.2 days ago, total size 120.0 MB across 45 files",
      "proposed_action": "delete_dir",
      "is_dir": true,
      "file_count": 45
    }
  ]
}
```

---

## Safety Architecture

- **Single-Pass High Performance Scan**: Fast parallel filesystem traversal without double scanning.
- **Fail-Closed Subtree Protection Guard**: Traverses candidate subtrees and fails closed on unreadable or permission-restricted subdirectories to prevent deleting protected credential, configuration, or agent memory files.
- **Fail-Closed Pre-Action Fingerprint Revalidation**: Revalidates candidate file size (`size_bytes`), modification time (`ModTime`), file item type (`IsDir`), and path existence directly before execution. Aborts deletion if any attribute mutated since the scan snapshot.
- **Unknown / Custom Pattern Report-Only Isolation**: Custom user patterns added via `+pattern` are classified as `unknown` risk class and are strictly report-only (`CanDelete = false`). They are never deleted automatically in `--apply` mode.
- **Injection-Safe Parameterized Trash Handlers**: Employs parameterized command invocation on Windows (`powershell -LiteralPath`) and macOS (`osascript argv`) to prevent shell injection or path escaping.
