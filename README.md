# stale-cleaner

> **What**: `stale-cleaner` is an interactive TUI tool that discovers and cleans stale build caches, AI agent logs, unused toolchain packages, and LLM weights across your system.
> **Why**: Use it to safely reclaim tens of gigabytes of disk space wasted by developer tools and local AI workflows without risking system file corruption or breaking active projects.

---

## Features

- **Full-Width TUI with Live Inspection**: Select items using `SPACE` or `TAB` with a compact bottom preview window displaying file metadata and line previews.
- **Declarative Rule Engine**: Configured via a simple JSON manifest to scan build caches (`.zig-cache`, `target/`), LLM weights (`.gguf`, `.safetensors`), AI agent sessions (`Codex`, `Claude`, `Gemini`, `Cursor`), and unused package binaries.
- **Native Uninstallation**: Automatically delegates removal of unused packages to native toolchains (`cargo uninstall`, `npm uninstall -g`, `pipx uninstall`, `swiftly uninstall`, etc.).
- **Live System Stats**: Displays real-time disk usage, candidate counts, and accumulated space savings.
- **Safeguards**: Protected path rules ensure credentials, active project configurations, and agent memories are never touched.

---

## Quick Start

```bash
# Run stale-cleaner interactively
stale-cleaner

# Custom age window (e.g. 7 days) and minimum size (e.g. 10 MB)
stale-cleaner -days 7 -min-size-mb 10

# Scan specific directories in preview mode
stale-cleaner -path ~/.cache -path /tmp -dry-run

# Exclude specific rules or add custom patterns
stale-cleaner -json_artifacts +*.bak
```

---

## Extending with Custom Manifests

`stale-cleaner` uses a declarative JSON manifest located at `~/.config/stale-cleaner/manifest.json`. You can easily add new scan rules, target types (`dir`, `file`, `any`), categories, and native uninstall commands without recompiling.

### Example `~/.config/stale-cleaner/manifest.json`

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

While general-purpose disk analyzers and language cleanup tools exist, `stale-cleaner` is built specifically for modern AI-assisted developer environments.

### Feature Comparison Matrix

| Tool | Ease of Extensibility | TUI Interactivity & Inspection | Full Developer & AI Agent Scope | Native Toolchain Uninstallation |
| :--- | :--- | :--- | :--- | :--- |
| **`stale-cleaner`** | **Declarative JSON rules** (Add any path, file pattern, or command without coding) | **Full-width line list** + live multi-line preview pane | **Covers build caches, temp dirs, AI Agent logs/sessions, LLM weights, & unused language binaries** | **Yes** (Delegates to `cargo`, `npm`, `pipx`, `swiftly`, `sdk`, `composer`, etc.) |
| **[Kondo](https://github.com/tbillington/kondo)** | Fixed rust codebase (Requires PRs/recompilation for new ecosystems) | Single-line list picker | Project build directories (`target`, `node_modules`, `venv`) | No (Direct directory removal only) |
| **[dua-cli](https://github.com/Byron/dua-cli)** | None (Strict file tree analyzer) | Interactive directory tree navigator | General disk usage across all files | No |
| **[ncdu](https://dev.lollogobaldo.com/ncdu/)** | None (Ncurses disk usage viewer) | Interactive directory tree navigator | General disk usage across all files | No |

---

## License

MIT License.
