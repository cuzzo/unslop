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
4. **`unknown`** *(Custom)*: Custom user-defined patterns.

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

# Move candidates to Trash instead of permanent deletion
unslop -trash -apply

# Enable permanent deletion mode (requires explicit -apply)
unslop -apply
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
      "size": 125829120,
      "age_days": 14.2,
      "category": "Cache Dir",
      "rule_id": "zig_cache",
      "risk_class": "regenerable",
      "reason": "Stale build cache unused for 14.2 days",
      "evidence": "Last modified 14.2 days ago, total size 120.0 MB across 45 files",
      "proposed_action": "delete_dir",
      "is_dir": true,
      "file_count": 45,
      "is_data": false
    }
  ]
}
```

---

## Safety Architecture

- **Single-Pass High Performance Scan**: Fast parallel filesystem traversal without double scanning.
- **Subtree Protection Guard**: Verifies candidate subtrees before removal to prevent deleting protected configuration, credentials, or agent memory files.
- **Pre-Deletion Path Re-Validation**: Verifies file modification times, file size, and item types directly before execution to prevent operating on stale scan snapshots.
- **Sanitized Previews**: Automatically redacts API keys, JWT tokens, and private keys in TUI preview panes.
- **No Shell Expansion**: Executes package manager actions via direct typed argument arrays without shell string parsing (`sh -c`).

---

## License

[BSD 3-Clause License](LICENSE.txt)

