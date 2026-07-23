# unslop

`unslop` is a high-performance developer workstation hygiene utility. It scans build caches, toolchain artifacts, package stores, AI agent logs, and model weights across your system, allowing you to interactively review and safely reclaim disk space.

---

## Installation

Install via standard Go tooling:

```bash
go install github.com/yahn/unslop/cmd/unslop@latest
```

### Dependencies
- **Go**: Version 1.22+
- **fzf (Recommended)**: `fzf` for interactive terminal UI filtering and selection. If `fzf` is not installed, `unslop` renders a structured text summary.

---

## Usage

```bash
# Interactively scan system for stale candidates (opens fzf TUI if available)
unslop

# Execute deletion / staging on selected items (moves to System Trash by default)
unslop -apply

# Preview scan results without modifying files
unslop -dry-run

# Override minimum inactivity threshold (e.g. 14 days) and minimum size (e.g. 50 MB)
unslop -min-days 14 -min-size-mb 50

# Load a custom rules manifest file
unslop -manifest ~/.config/unslop/manifest.json

# Opt-in to scan and delete user-data directories (e.g. LLM model weights, agent histories)
unslop -include-data -apply-data

# Perform permanent deletion bypassing the system Trash
unslop -apply -force-permanent
```

---

## Manifest Configuration

`unslop` uses a JSON manifest to define scanning rules, risk classifications, and default thresholds.

### Manifest File Locations
`unslop` checks for a manifest file in the following order:
1. Custom manifest passed via `-manifest /path/to/manifest.json`
2. `~/.unslop.json`
3. `~/.config/unslop/manifest.json` (or `$XDG_CONFIG_HOME/unslop/manifest.json`)
4. Embedded default `manifest.json`

### Extending the Manifest

You can customize `~/.config/unslop/manifest.json` to add custom target folders and files, tag them for display in the interactive UI, and adjust default thresholds:

```json
{
  "version": 1,
  "default_days": 7.0,
  "default_min_size_mb": 10.0,
  "rules": [
    {
      "id": "my_custom_cache",
      "name": "My Custom Build Cache",
      "target": "dir",
      "patterns": [".my-cache", "tmp-build-*"],
      "category": "Custom Cache",
      "risk_class": "regenerable",
      "min_size_mb": 5.0
    },
    {
      "id": "custom_log_files",
      "name": "App Debug Logs",
      "target": "file",
      "patterns": ["*.log", "debug-*.txt"],
      "category": "Log Files",
      "risk_class": "regenerable",
      "min_size_mb": 1.0
    }
  ]
}
```

### Manifest Fields Reference

| Field | Type | Description |
| :--- | :--- | :--- |
| `version` | `int` | Manifest schema version (currently `1`). |
| `default_days` | `float` | Default inactivity threshold in days. Overridden by CLI flag `-min-days` (or `-days`). |
| `default_min_size_mb` | `float` | Default minimum candidate size in MB. Overridden by CLI flag `-min-size-mb`. |
| `rules` | `array` | List of rule definitions for directory and file matching. |

#### Rule Definition Fields

| Field | Type | Description |
| :--- | :--- | :--- |
| `id` | `string` | Unique identifier for the rule (e.g. `"cargo_target"`). |
| `name` | `string` | Human-readable name displayed in summary and logs. |
| `target` | `string` | Target type: `"dir"`, `"file"`, or `"any"`. |
| `patterns` | `array` | Glob patterns to match directory or file names (e.g. `["node_modules", ".cache"]`). |
| `category` | `string` | Display label shown in the TUI (e.g. `"Node Modules"`, `"Rust Target"`). |
| `risk_class` | `string` | Risk classification (`"regenerable"`, `"package-managed"`, `"user-data"`, `"unknown"`). |
| `marker_files` | `array` | *(Optional)* Parent directory marker files required for rule to match (e.g. `["Cargo.toml"]`). |
| `internal_marker_files` | `array` | *(Optional)* Internal directory marker files required inside candidate (e.g. `["package.json"]`). |
| `min_size_mb` | `float` | *(Optional)* Rule-specific minimum size override in MB. |

---

## Risk Classes

Every rule specifies a `risk_class` that governs safety and deletion behavior in the UI:

1. **`regenerable`** *(Safe for Deletion)*: Build artifacts and compiler outputs (`.zig-cache`, `target/`, `node_modules`) that can be recreated by build tools.
2. **`package-managed`** *(Toolchain)*: System toolchain directories mapped to package managers (`cargo`, `pipx`, `npm`, `swiftly`, `sdkman`, `dotnet`, `zvm`). Classified as report-only unless explicitly uninstalled.
3. **`user-data`** *(Opt-In Only)*: LLM model weights, agent session histories, and data dumps. Excluded unless `-include-data` and `-apply-data` are supplied.
4. **`unknown`** *(Report-Only)*: Unclassified patterns. Always isolated as report-only.

---

## Safety Architecture

- **Single-Pass Parallel Traversal**: High-speed parallel filesystem crawler with real-time status output.
- **Fail-Closed Subtree Guard**: Aborts directory deletion if unreadable permissions or protected agent credentials/keys are found inside.
- **Pre-Action Fingerprint Revalidation**: Checks file sizes and modification timestamps right before deletion to ensure data has not changed since the scan snapshot.
- **Transactional Trash Quarantine**: Moves items into isolated quarantine before deletion or recycling.
