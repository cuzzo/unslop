# Architecture & Design Specification: `unslop repo` & `repowise unslop`

## 1. Overview & Goal

`unslop repo` is a VCS history hygiene subcommand designed to analyze repository history (currently supporting Git, structured for multi-VCS extensibility) and discover historical artifacts that bloat repository size.

### Primary Objectives:
- **Git History Scanning**: Inspect repository commits, trees, and blobs to locate historical bloat without modifying repository history directly.
- **Artifact Classification**:
  1. **Debug & Large Binaries**: Binary files (e.g. `.exe`, `.so`, `.a`, `.dll`, `.tar`, `.zip`, `.iso`, `.pdf`, `.mp4`) added and deleted or currently existing, with specialized detection for debug symbols (`.pdb`, `.dSYM`, `.elf`, `.o`, `.obj`, `.gch`, `.idb`, `.ilk`, `.map`).
  2. **Deleted-Then-Ignored Artifacts**: Files committed, deleted in subsequent commits, and subsequently/contemporaneously added to `.gitignore` or VCS ignore rules (`.hgignore`).
  3. **Garbage & Dump Files**: Temporary dumps, logs, and scratch files (`.json` data dumps, `.log`, `.tmp`, `.bak`, `.swp`, `.ds_store`, `.thumbs.db`, `coverage.json`, `trace.json`) that were added and deleted.
  4. **Dependency & Package Dumps**: Accidental commits of dependency trees (`node_modules/`, `vendor/`, `venv/`, `.venv/`, `target/`, `Pods/`, `dist/`, `build/`, `.gradle/`, `.nuget/`).
- **SotA History Rewriting Integration**: After interactive selection via `unslop` UI (or formatted text fallback), `unslop repo` writes a target paths filter manifest (`unslop-git-filter.txt`) compatible with `git-filter-repo`. It outputs explicit instructions on running `git-filter-repo --invert-paths --paths-from-file unslop-git-filter.txt`.
- **`repowise` Delegation**: `repowise unslop` acts as a frontend CLI wrapper in Rust that detects if the `unslop` binary is installed in `$PATH`, delegating execution to `unslop repo .` or recommending installation steps if missing. `repowise -h` lists `unslop` with a note that it requires separate installation.

---

## 2. Architecture & VCS Abstraction

```
                   +-----------------------+
                   |  repowise unslop      | (Rust Frontend Wrapper)
                   +-----------+-----------+
                               |
                   +-----------v-----------+
                   |  unslop repo [path]   | (Go Subcommand & Scanner)
                   +-----------+-----------+
                               |
               +---------------+---------------+
               |                               |
    +----------v----------+         +----------v----------+
    |   VCSAnalyzer       |         |   Interactive UI    |
    |   (Interface)       |         |   (fzf / Text)      |
    +----------+----------+         +----------+----------+
               |                               |
    +----------v----------+         +----------v----------+
    |   GitAnalyzer       |         | Filter Manifest     |
    |   (Git Implementation)        | Generator           |
    +---------------------+         +---------------------+
```

### VCS Abstraction (`internal/repo/vcs.go`)
```go
type VCSKind string

const (
    VCSGit VCSKind = "git"
)

type HistoryCandidate struct {
    ID           int
    Path         string
    Size         int64
    Category     string
    RiskClass    string
    Status       string // "deleted" or "existing"
    IsDebug      bool
    CommitCount  int
    CanDelete    bool
}

type VCSAnalyzer interface {
    Kind() VCSKind
    Detect(repoPath string) bool
    AnalyzeHistory(repoPath string, opts ScanOptions) ([]HistoryCandidate, error)
}
```

---

## 3. History Detection Rules & Heuristics

1. **Large & Debug Binary Rules**:
   - Extensions: `.pdb`, `.dsym`, `.elf`, `.o`, `.obj`, `.gch`, `.idb`, `.ilk`, `.map`, `.exe`, `.dll`, `.so`, `.dylib`, `.a`, `.lib`, `.bin`, `.iso`, `.tar`, `.gz`, `.zip`, `.7z`, `.pdf`, `.mp4`, `.png`, `.jpg`.
   - Heuristics: High entropy / binary null-byte check + path pattern matching.
2. **Deleted-Then-Ignored Rules**:
   - History diff inspection: File path present in early commits, removed in commit $C_k$, and path/pattern appears in `.gitignore` or `.hgignore` in commit $C_m$ ($m \ge k$).
3. **Garbage & Scratch File Rules**:
   - Pattern matching on `.json` files, `.log`, `.tmp`, `.bak`, `.swp`, `.ds_store`, `coverage.json`, `trace.json` that are added and deleted.
4. **Accidental Dependency Directory Dumps**:
   - Path prefixes matching `node_modules/`, `vendor/`, `venv/`, `.venv/`, `target/`, `Pods/`, `dist/`, `build/`, `.gradle/`, `.nuget/`.

---

## 4. `git-filter-repo` Integration & Output Specification

Upon selecting candidates in `unslop repo`:
1. `unslop` writes `unslop-git-filter.txt` containing one relative path/pattern per line:
   ```
   node_modules/
   bin/debug.pdb
   data/scratch_dump.json
   ```
2. Displays execution instructions:
   ```
   Successfully generated Git filter manifest: unslop-git-filter.txt

   To safely purge selected candidates from Git history using git-filter-repo, run:
       git-filter-repo --invert-paths --paths-from-file unslop-git-filter.txt

   Note: git-filter-repo is the State-of-the-Art Git history rewriting tool.
   Ensure you have created a full backup or mirror clone before execution.
   ```

---

## 5. `repowise` Delegation Specification

In `repowise` (Rust):
- `repowise unslop [args...]`:
  - Locates `unslop` binary using PATH search (`which` / `Command::new("unslop")`).
  - If missing: Prints error message recommending installation:
    `Error: 'unslop' binary is not installed or not found in PATH.`
    `Install unslop using: go install github.com/yahn/unslop/cmd/unslop@latest`
  - If present: Forks process to `unslop repo [args...]`.
- `repowise -h` / `repowise unslop -h`:
  - Lists `unslop` subcommand: `unslop - Interactively analyze repository VCS history for bloat candidates and export git-filter-repo manifests (Note: requires 'unslop' binary installed separately)`.

---

## 6. Implementation Tasks & Verification Plan

- [x] **Task 1: Design Specification**: Create `~/unslop/docs/agents/repo.md`.
- [ ] **Task 2: Go VCS Abstraction & Git Analyzer**: Implement `internal/repo/vcs.go` and `internal/repo/git.go` in `unslop`.
- [ ] **Task 3: Detection Rules Engine**: Implement `internal/repo/rules.go` with rule sets for Debug Binaries, Deleted-Then-Ignored, Garbage JSON/Logs, and Dependency Dumps.
- [ ] **Task 4: Interactive TUI & Manifest Exporter**: Implement `internal/repo/ui.go` and `internal/repo/writer.go` for manifest writing and `fzf`/text interaction.
- [ ] **Task 5: `unslop repo` CLI Entrypoint**: Wire subcommand `repo` in `cmd/unslop/main.go` and `cmd/unslop/repo.go`.
- [ ] **Task 6: Go Unit & Integration Tests**: Comprehensive tests in `internal/repo/*_test.go` and `cmd/unslop/*_test.go` achieving > 95% LoC coverage.
- [ ] **Task 7: `repowise unslop` Subcommand**: Implement `unslop` subcommand delegation, binary discovery, and help text in `repowise` (Rust).
- [ ] **Task 8: Rust Integration Tests**: Add `repowise` integration tests for `unslop` flag handling, help output, and binary execution fallback.
- [ ] **Task 9: LoC Coverage & Quality Verification**: Validate > 95% test line coverage for all new code added in Go and Rust.
