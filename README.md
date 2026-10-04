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
- **fzf 0.73 or later**: Required for interactive Repos, including timer-driven progress and stable selections during refresh. Without fzf, scans print a text summary; `-apply` fails with an installation hint. See the [fzf changelog](https://github.com/junegunn/fzf/blob/master/CHANGELOG.md).

### macOS

```bash
brew install go fzf
go install ./cmd/unslop
```

Run the installation command from this checkout. Ensure Go's bin directory is on
`PATH`. The checked-in `./unslop` launcher also works on macOS and Linux: it builds
a temporary native executable for each invocation and preserves your working
directory. An installed executable avoids that build step.

macOS cleanup uses the native `trash` command, with Finder through `osascript` as
a fallback. The fallback may require Automation permission. Access errors stop
cleanup and name the inaccessible paths. Previews still show accessible
candidates and return a nonzero status to signal the incomplete scan. Check your terminal's Files & Folders
permissions, or Full Disk Access when scanning protected locations. See
[Apple's file-access guidance](https://support.apple.com/en-ph/guide/security/secddd1d86a6/web).

Default scans include your home directory and the user temporary directory
(`$TMPDIR` on macOS). Xcode DerivedData is a build-cache candidate. Homebrew's
download cache is report-only; use `brew cleanup` to manage it. Standalone native
binaries and libraries are report-only because their extensions do not prove
they are disposable build output.

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
unslop -include-data -apply -apply-data

# Perform permanent deletion bypassing the system Trash
unslop -apply -force-permanent
```

---

## Agent sessions

Antigravity and pi histories are user data. Preview them with:

```bash
unslop -include-data -dry-run -min-size-mb 0.1
```

Cleanup requires `-include-data -apply -apply-data`, followed by selection and
confirmation. Recently modified items remain excluded by the inactivity threshold.
Credentials and configuration roots remain protected.

- pi: individual JSONL files under `~/.pi/agent/sessions/<project>/`.
- Antigravity: individual artifact folders under `~/.gemini/antigravity*/brain/`
  for the `antigravity`, `antigravity-cli`, `antigravity-ide`, and
  `antigravity-backup` stores. Conversation stores are reviewed as whole
  directories so database files and their sidecars stay together. Context memory
  under `implicit/` is user data, not disposable cache.

The default pi layout is defined in [pi's session manager](https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/src/core/session-manager.ts).
Google documents Antigravity's transcript layout in its [hooks reference](https://www.antigravity.google/docs/hooks).
For custom session locations, provide `-path` and an explicit user-data manifest
rule. Close the relevant agent before cleaning its history.

---

## Repositories and unmerged work

```bash
# Discover repositories under home and group their registered worktrees
./unslop repos

# Files opens first; press r for the Repos tab
./unslop

# Optionally limit discovery to particular locations or one repository
./unslop repos -path ~/dev -path ~/.codex/worktrees
./unslop repos -repo ~/dev/giga

# Print evidence without the terminal selector
./unslop repos -non-interactive
./unslop repos -json
```

Files opens immediately and fills the list during scanning. **r** opens Repos;
**f** returns to Files. **/** enters search, where those letters become ordinary
search text. **Ctrl-W** and **Ctrl-F** also switch tabs. Leaving a tab stops its
scan. Files cleanup flags survive a round trip.

Repos shows duplicate groups: registered worktrees of one Git repository, or
separate clones with the same normalized **origin** URL. SSH and HTTPS forms of
an origin share a group. A shared upstream alone does not group different forks.
Standalone repositories stay out of the selector. Git markers, checkout roots,
and worktree registry ownership are checked before a checkout appears. Missing,
stale, or replaced checkouts remain errors in the report.

Discovery runs in the background and adds groups as it finds them. Its loading
bar estimates completed versus known pending directories, and changes as the
search discovers more directories. It measures discovery work, not time left.
The default search starts at home. Dependency/build directories, Trash, Git
internals, and `.giga` artifacts are skipped; registered worktrees outside the
search roots still come from Git's registry.

**Enter** opens the selected group inside the TUI. The branch list shows distinct
work from the last **14 days**, including branches without a checkout and local
work absent from cached origin refs. Select a branch to see commit IDs, dates,
subjects, and aliases in the preview. **Shift-Up/Down** scrolls commits.
**r** or **Esc** returns to groups; **f** opens Files; **q** quits.
Change the window with `./unslop repos -days 7`. The date window affects display,
not the cleanup safety check: old unmerged work still blocks a candidate.

The main repository strongly favors the original unsuffixed path, such as
`~/dev/giga` over `giga-*`, then a repository that owns registered worktrees.
Within that repository, the main branch favors history containing the most
other branch tips. Ties favor its primary checkout's branch, then recent commit
activity, checked-out branches, local work absent from origin, and commit recency.
The chosen main repository and branch are shown in the footer and JSON report.

A clone is a cleanup candidate only if **every local and cached remote branch**
and detached checkout tip is fully retained by a local branch in the main
repository. A linked worktree needs its full history retained by another local
branch in the same repository. Git's commit parent graph proves ancestry;
cherry-picks, rebases, and matching patches alone never count as full merges.
Independent clones are compared through temporary, read-only object lookup;
scans do not fetch or change Git configuration.

Candidates must also be clean, readable, unlocked, and free of untracked,
ignored, and stashed work. The main repository, bare repositories, and clones
that still own linked worktrees remain protected. HEADs and branch refs are
rechecked during analysis. Failed or incomplete checks yield no candidates.
These are snapshots: recheck before removing anything and use Git's worktree
commands. Repos does not delete directories, branches, or history.

Text and JSON reports analyse all discovered groups; explicit `-repo` also
supports inspecting a standalone repository. JSON includes branch evidence in
`projects` and analysed checkout flags in `worktrees`. Filesystem and metadata
errors remain in the report and produce a nonzero exit status. `worktrees`
remains an alias for `repos`; `repo` is the separate history-cleanup command.

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

Patterns without a slash match names. Relative patterns with slashes match path
suffixes at directory boundaries. `~/` anchors a pattern to your home directory;
absolute patterns match the full path. Each `*` matches within one path component.

---

## Risk Classes

Every rule specifies a `risk_class` that governs safety and deletion behavior in the UI:

1. **`regenerable`**: Recognized build caches and dependencies (`.zig-cache`, `target/`, `node_modules`) that can be recreated by build tools.
2. **`package-managed`** *(Toolchain)*: System toolchain directories mapped to package managers (`cargo`, `pipx`, `npm`, `swiftly`, `sdkman`, `dotnet`, `zvm`). Classified as report-only unless explicitly uninstalled.
3. **`user-data`** *(Opt-In Only)*: LLM model weights, agent session histories, and data dumps. Scanning requires `-include-data`; deletion also requires `-apply-data`.
4. **`unknown`** *(Report-Only)*: Unclassified patterns. Always isolated as report-only.

---

## Safety Architecture

- **Single-Pass Parallel Traversal**: High-speed parallel filesystem crawler with real-time status output.
- **Fail-Closed Subtree Guard**: Aborts directory deletion if unreadable permissions or protected agent credentials/keys are found inside.
- **Pre-Action Fingerprint Revalidation**: Checks file sizes and modification timestamps right before deletion to ensure data has not changed since the scan snapshot.
- **Transactional Trash Quarantine**: Moves items into isolated quarantine before deletion or recycling.

## Developer checks

Run `go test -race ./...` and `go vet ./...` on macOS or Linux. `giga.yml` uses
Giga's Go preset, resolving installed analyzer commands from `PATH` instead of a
machine-specific checkout. Run `giga config validate`, `giga doctor`, then
`giga sync --profile full` in a clean checkout. Failed producers remain failed;
missing analyzer output is never replaced with an empty success report.
