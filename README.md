# unslop

> **What**: `unslop` is an interactive TUI tool that discovers and cleans stale build caches, AI agent logs, unused toolchain packages, and LLM weights across your system.
> **Why**: Use it to safely reclaim tens of gigabytes of disk space wasted by developer tools and local AI workflows without risking system file corruption or breaking active projects.

---

## Installation

Install via standard Go tooling:

```bash
go install github.com/yahn/unslop@latest
```

---

## Features

- **Full-Width TUI with Live Inspection**: Select items using `SPACE` or `TAB` with a compact bottom preview window displaying file metadata and line previews.
- **Declarative Rule Engine**: Configured via a simple JSON manifest to scan build caches (`.zig-cache`, `target/`), LLM weights (`.gguf`, `.safetensors`), AI agent sessions (`Codex`, `Claude`, `Gemini`, `Cursor`), and unused package binaries.
- **Native Uninstallation**: Automatically delegates removal of unused packages to native toolchains (`cargo uninstall`, `npm uninstall -g`, `pipx uninstall`, `swiftly uninstall`, etc.).
- **Live System Stats & Exact Progress**: Displays real-time disk usage, exact file progress percentage, scanning throughput (`files/s`), and accumulated candidate space in GB.
- **Safeguards**: Protected path rules ensure credentials, active project configurations, and agent memories are never touched.

---

## Quick Start

```bash
# Run unslop interactively
unslop

# Custom age window (e.g. 7 days) and minimum size (e.g. 10 MB)
unslop -days 7 -min-size-mb 10

# Scan specific directories in preview mode
unslop -path ~/.cache -path /tmp -dry-run

# Exclude specific rules or add custom patterns
unslop -json_artifacts +*.bak
```

---

## Configuration & Custom Manifest Hierarchy

`unslop` resolves configuration automatically using the following order of precedence:

1. **Explicit CLI Flag**: `-manifest /path/to/custom.json`
2. **User Home Override**: `~/.unslop.json` (Easily override rules from your home folder)
3. **XDG Config Directory**: `~/.config/unslop/manifest.json` (or `$XDG_CONFIG_HOME`)
4. **Embedded Default Binary Manifest**: Embedded at compile time via `//go:embed` (Auto-creates `~/.config/unslop/manifest.json` on first run if no config exists).

### Example Custom Manifest (`~/.unslop.json`)

```json
{
  "rules": [
    {
      "id": "llm_weights",
      "name": "Local LLM Models",
      "target": "file",
      "patterns": ["*.gguf", "*.safetensors", "*.ckpt"],
      "category": "LLM Model",
      "min_size_mb": 100.0
    },
    {
      "id": "swift_toolchain",
      "name": "Swift Toolchains",
      "target": "dir",
      "patterns": ["*/.local/share/swiftly/toolchains/*"],
      "category": "UNUSED (Swift)",
      "uninstall_cmd": "swiftly uninstall {name}"
    },
    {
      "id": "custom_cache",
      "name": "Custom Project Cache",
      "target": "dir",
      "patterns": [".my-cache", "tmp-build-*"],
      "category": "Custom Cache"
    }
  ]
}
```

---

## Other Options & Comparison

While general-purpose disk analyzers and language cleanup tools exist, `unslop` is built specifically for modern AI-assisted developer environments.

### Feature Comparison Matrix

| Tool | Ease of Extensibility | TUI Interactivity & Inspection | Full Developer & AI Agent Scope | Native Toolchain Uninstallation |
| :--- | :--- | :--- | :--- | :--- |
| **`unslop`** | **Declarative JSON rules** (Add any path, file pattern, or command without coding) | **Full-width line list** + live multi-line preview pane | **Covers build caches, temp dirs, AI Agent logs/sessions, LLM weights, & unused language binaries** | **Yes** (Delegates to `cargo`, `npm`, `pipx`, `swiftly`, `sdk`, `composer`, etc.) |
| **[Kondo](https://github.com/tbillington/kondo)** | Fixed rust codebase (Requires PRs/recompilation for new ecosystems) | Single-line list picker | Project build directories (`target`, `node_modules`, `venv`) | No (Direct directory removal only) |
| **[dua-cli](https://github.com/Byron/dua-cli)** | None (Strict file tree analyzer) | Interactive directory tree navigator | General disk usage across all files | No |
| **[ncdu](https://dev.lollogobaldo.com/ncdu/)** | None (Ncurses disk usage viewer) | Interactive directory tree navigator | General disk usage across all files | No |

---

## License

MIT License.
