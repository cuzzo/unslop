# unslop

> **What**: `unslop` is a high-performance interactive TUI tool that discovers and cleans stale build caches, AI agent logs, unused toolchain packages, and LLM weights across your system.
> **Why**: Use it to safely reclaim gigabytes of disk space wasted by developer build tools and local AI workflows with multi-layered path safeguards, structured package manager uninstallation, and pre-deletion path re-validation.

---

## Installation

Install via standard Go tooling:

```bash
go install github.com/yahn/unslop@latest
```

---

## Features

- **Full-Width TUI with Live Inspection**: Select items using `SPACE` or `TAB` with a bottom preview window displaying line previews and item metadata.
- **Fail-Closed Declarative Engine**: Configured via JSON rule manifests to scan build caches (`.zig-cache`, `target/`), LLM weights (`.gguf`, `.safetensors`), AI agent sessions (`Codex`, `Claude`, `Gemini`, `Cursor`), and verified unused package binaries.
- **Structured Toolchain Uninstallation**: Maps installed package inventories (`~/.cargo/.crates.toml`, `pipx`, `npm`, `swiftly`, `sdkman`, `dotnet`, `composer`) and executes uninstallation via direct argument arrays without shell expansion (`sh -c`).
- **Data vs Cache Categorization**: Default scans focus on safe, regenerable build caches (`.zig-cache`, `target/`, `.gradle`, `node_modules/.cache`). User data and model weights require explicit `--include-data` review opt-in.
- **Multi-Layered Safeguards**:
  - **Subtree Protection Guard**: Verifies candidate subtrees before removal to prevent deleting protected configuration, credentials, or agent memory files.
  - **Pre-Deletion Path Re-Validation**: Verifies file modification times, file size, and item types directly before execution to prevent operating on stale scan snapshots.
  - **System Trash Support**: Optional `--trash` flag moves items to system trash instead of permanent deletion.

---

## Quick Start

```bash
# Run unslop interactively (scans safe regenerable build caches)
unslop

# Include user data, AI agent sessions, and LLM weights for review
unslop -include-data

# Move candidates to Trash instead of permanently deleting
unslop -trash

# Custom age window (e.g. 14 days) and minimum size (e.g. 10 MB)
unslop -days 14 -min-size-mb 10

# Scan specific directories in dry-run mode
unslop -path ~/.cache -path /tmp -dry-run
```

---

## Configuration & Manifest Hierarchy

`unslop` resolves manifest rules in the following strict order of precedence:

1. **Explicit CLI Flag**: `-manifest /path/to/custom.json` (Fails closed immediately if invalid or missing)
2. **User Home Override**: `~/.unslop.json`
3. **XDG Config Directory**: `~/.config/unslop/manifest.json` (or `$XDG_CONFIG_HOME`)
4. **Embedded Default Manifest**: Embedded at compile time via `//go:embed`.

---

## Comparison

| Tool | Declarative Custom Rules | Structured Toolchain Uninstallation | Subtree Safeguards & Re-Validation | Review-Only Data Opt-In |
| :--- | :--- | :--- | :--- | :--- |
| **`unslop`** | **Yes** (JSON manifest) | **Yes** (cargo, npm, pipx, swiftly, sdkman, dotnet, composer) | **Yes** (Subtree guard + `lstat` snapshot recheck) | **Yes** (`--include-data`) |
| **[Kondo](https://github.com/tbillington/kondo)** | No | No (Direct directory removal) | No | No |
| **[dua-cli](https://github.com/Byron/dua-cli)** | No | No | No | No |
| **[ncdu](https://dev.lollogobaldo.com/ncdu/)** | No | No | No | No |

---

## License

MIT License.
