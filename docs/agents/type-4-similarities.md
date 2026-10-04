# Type-4 similarities and library reinventions

Status: audit findings and proposals, not applied changes. Source checkpoint:
`c6a1d8b22d7f7bf8854b3931617a7dbf52957717`. The current production source
matches that checkpoint. Reproduce the source check and probes with
`python3 metrics/src/architecture_audit.py`; inspect
[the evidence](../../metrics/data/architecture-audit.json) and
[the probe source](../../metrics/src/architecture_probe.go).

## What was found

The terminal string filter and repeated progress glyphs have small standard-library
replacements supported by differential checks. Larger candidates share a computation
or system responsibility, but their complete contracts are not equivalent. No large
semantic clone was proved removable in this pass. The target is cumulative additional
savings across useful simplifications; it does not require a single large refactor.

Here, Type-4 means equivalent computation despite different syntax or control flow.
A shared API call, similar name, or overlapping purpose is only a lead. Each finding
below states the contract that must survive and the limit of the evidence.

| Candidate | Location | Replacement or overlap | Finding |
| --- | --- | --- | --- |
| Terminal rune filter | `internal/ui/ui.go:SanitizeTerminalString` | `strings.Map` | Supported stdlib replacement; retain the exact control-character predicate. |
| Progress glyph loops | `internal/ui/ui.go:RenderProgressBar` | `strings.Repeat` | Supported for the tested finite-input domain; retain clamping and nonpositive-width behavior. |
| Git ancestry and recent history | `internal/worktree/projects.go:branchHistory`, `AnalyzeProject` | Git revision traversal and `merge-base` | Native-engine reinvention candidate; replacement may hurt subprocess cost and does not remove safety/ranking policy. |
| Live selector protocol | `internal/ui/live.go`, `internal/worktree/live.go`, `internal/repo/ui.go` | Bubble Tea/Bubbles or tview | Reject the rewrite on current evidence: limited estimated savings and no demonstrated user/performance benefit. |
| Subtree inspection | `scanner.InspectSubtree`, `platform.ContainsProtectedPath`, `platform.ContainsMountOrReparsePoint` | Related `filepath.WalkDir` traversals | Partial semantic overlap; early exit, metadata, boundaries, and failure policies differ. |
| Selection decoding | `ui.selectedFiles`, `worktree.selectedOutput`, `repo.RunRepoUI` | Shared `ui.SelectionTokens`, exit and token handling | Related orchestration with different eligibility and result contracts; avoid counting whole selectors as clones. |
| Executable classification | `scanner.IsExecutableBinary` | MIME sniffing or `debug/elf`, `debug/macho`, `debug/pe` | Reject as a direct replacement: MIME/type parsing does not provide the existing policy. |
| Linux trash | `executor.moveToTrash`, `platform.MoveToTrashOS` | Desktop trash utilities | Native fallback plus utility delegation, not two interchangeable implementations. |

## Complete costs and cumulative savings

| Lead | Existing lines in replacement boundary | Replacement lines | Net lines removed | Evidence status |
| --- | ---: | ---: | ---: | --- |
| Terminal filter [S] | 10 | 8 | 2 | Actual research draft measured; differential probe passes; unapplied. |
| Progress bar [P] | 23 | 16 | 7 | Actual research draft measured; probe passes within its recorded domain; unapplied. |
| Native Git [G] | 274 | 230–290 | −16–44 | Planning estimate including retained safety/ranking policy; no parity/performance proof. |
| Shared fresh inspection [I] | 127 | 110–170 | −43–17 | Planning estimate including policies, adapters, and platform access; no complete replacement proved. |
| Selection decoding | — | — | Unsized; no credit | Common token decoder already exists; no smaller complete selector/cancellation design demonstrated. |
| Executable classification | — | — | Unsized; no credit | Direct stdlib/MIME replacement rejected as behaviorally different. |
| Linux trash | — | — | Unsized; no credit | No replacement shown to preserve native fallback and recovery contracts. |
| UI rewrite [U] | 463 | 290–460 | 3–173 | Rejected; excluded from the cumulative proposal. |

Metric provenance for each table row:

- [S] 10 existing, 8 draft, 2 net
  (metrics/data/architecture-audit.json#stdlib_draft_sizes.terminal_filter, python3 metrics/src/architecture_audit.py).
- [P] 23 existing, 16 draft, 7 net
  (metrics/data/architecture-audit.json#stdlib_draft_sizes.progress_bar, python3 metrics/src/architecture_audit.py).
- [G] 274 gross, 230–290 estimated replacement, −16–44 estimated net
  (metrics/data/architecture-audit.json#plans.native_git, python3 metrics/src/architecture_audit.py).
- [I] 127 gross, 110–170 estimated replacement, −43–17 estimated net
  (metrics/data/architecture-audit.json#plans.single_inspection, python3 metrics/src/architecture_audit.py).
- [U] 463 gross, 290–460 estimated replacement, 3–173 estimated net
  (metrics/data/architecture-audit.json#plans.typed_ui, python3 metrics/src/architecture_audit.py).

The stdlib drafts replace 33 lines with 24, a measured draft reduction of 9 lines
(metrics/data/architecture-audit.json#stdlib_draft_totals, python3 metrics/src/architecture_audit.py).
They are in [the research probe](../../metrics/src/architecture_probe.go), not production.
Counts are inclusive physical declaration spans, including internal comments/blanks;
tests, docs, and external library implementations are excluded.

The disjoint stdlib, native-Git, and inspection boundaries give a cumulative planning
range of −50 to 70 net lines removed
(metrics/data/architecture-audit.json#cumulative_type4_plan, python3 metrics/src/architecture_audit.py).
This arithmetic does not prove those savings are safely available: Git and inspection
still lack complete replacement evidence. The target remains unmet by the inspected
leads, even cumulatively. Unsized or rejected substitutions receive no savings credit.
No production deletion was applied during this audit.

The UI proposal is a rewrite, and transferring the transport into a library does not
establish better behavior or performance. Do not pursue it to meet the deletion target.
Favor independent localized simplifications and require actual net diffs before
counting them as eliminated debt.

## Standard-library replacements

### Terminal string filtering

[SanitizeTerminalString](../../internal/ui/ui.go) ranges over runes, drops the
existing ASCII control characters, and writes the rest with `strings.Builder`.
`strings.Map` supplies this transform directly:

```go
return strings.Map(func(r rune) rune {
    if r < 32 || r == 127 {
        return -1
    }
    return r
}, s)
```

The differential probe covers every single-byte and double-byte input, plus selected
Unicode, malformed UTF-8, and terminal-control inputs. It reports 65,800 cases and
zero mismatches (metrics/data/architecture-audit.json#stdlib_probes.sanitizer,
python3 metrics/src/architecture_audit.py). This is strong evidence for the localized
replacement, not a proof over every possible string. Preserve invalid UTF-8 decoding;
do not substitute a byte-only filter or broaden which Unicode characters are removed.

### Progress glyph repetition

[RenderProgressBar](../../internal/ui/ui.go) builds the filled and empty portions
with loops. Use `strings.Repeat` for those portions while keeping the percentage
clamp, filled-length rounding, and `[]` result for nonpositive widths.

The differential probe reports 11,544 cases and zero mismatches
(metrics/data/architecture-audit.json#stdlib_probes.progress,
python3 metrics/src/architecture_audit.py). Its domain is finite percentages and the
recorded width range. It does not establish NaN behavior, overflow behavior, allocation
limits, or an unbounded input contract. `strings.Repeat` panics for negative counts,
so deleting the width handling would not be equivalent.

These are small simplifications; their measured research-draft sizes are in the table
above. The draft size is not an applied production reduction or a general input proof.

## Larger semantic-overlap candidates

### Git already owns the commit graph

[AnalyzeProject](../../internal/worktree/projects.go) reads pooled Git objects,
parses a history graph, and calls `branchHistory` to traverse reachable commits per
head. Native Git can answer ancestry and recent/distinct-history questions.

The overlap is the traversal algorithm, not the complete analysis. Repository identity,
canonical-copy preference, main-branch ranking, shallow-history rejection, independent
object retention, stash/dirty/local-file checks, and ref/HEAD revalidation remain
application policy. Git queries must preserve ancestry across copies and cancellation.
Commit-date filtering must also handle non-monotonic timestamps; simply pruning traversal
with `git log --since` is not automatically equivalent to filtering all reachable commits.
Compare `--since-as-filter` and its required Git-version support before using it.

See [architectural-simplification.md](architectural-simplification.md) for complete
replacement costs and the performance reason to retain the current approach for now.

### UI lifecycle versus a common dependency

`RunLive` translates typed results into NUL/tab rows, temporary files, shell actions,
and fzf output tokens. Files, Repos, branches, and history selection each own adapters.
Bubble Tea provides `Model.Update`, `Program.Send`, context cancellation, and terminal
lifetime; Bubbles provides list filtering and a viewport. tview provides an application,
tables, previews, and `QueueUpdateDraw`; fuzzy matching needs another library or code.

Inspected APIs are from the locally cached Bubble Tea/Bubbles, tview, and sahilm/fuzzy
sources listed in `architecture-audit.json#inspected_external_source_hashes`.
This is an API feasibility check, not a current-version dependency recommendation or a
working replacement. Multi-select, stable selection across updates, key bindings,
search semantics, preview navigation, headless behavior, and shutdown still need glue.
Dependency maintenance and transitive code must be counted as transferred ownership.

### Walkers and selectors

The executor repeats protection, boundary, and subtree checks immediately before
deletion. A single fresh inspection could share traversal, but discovery and execution
are separate observations. Reusing the discovery result would weaken safety.
Protection can stop early without reading metadata; boundary checking needs platform
device identity and rejects symlinks/reparse points; size/activity inspection accumulates
metadata and supports cancellation. Historical file-size estimates have another error
policy and purpose. These differences prevent an equivalence claim for the whole walkers.

Likewise, Files filters selected items by deletion eligibility, Repos returns a group
and navigation intent, and history returns items for manifest generation. Shared token
decoding already exists. A generic selector framework could add more state and adapters
than it removes.

## False positives to reject

- MIME detection and executable policy are different: extensions can classify unreadable
  files, executable permission gates magic-byte checks, and shebang scripts are excluded.
  Standard binary parsers would require more data and change malformed-file behavior.
- `Groups` is a small transitive grouping algorithm over registry and remote identities;
  a generic graph dependency does not remove the remote-normalization policy.
- Journal atomic writes and UI atomic writes have different durability and recovery
  contracts; rename syntax alone does not make them semantic duplicates.
- A trash utility alone does not replace isolation, durable journal phases, rollback,
  or orphan recovery; removing those would lose supported recovery behavior.
- `git-filter-repo --analyze` is worth comparing with history-bloat discovery, but no
  equivalence was established for lifecycle classification, ignore checks, estimates,
  selection, and manifest output; dropping that command is a product change.

## What Giga supplied

Decomplex's existing dataflow-clone detector uses normalized control/data dependence
subgraphs, including renamed/reordered code. Its selected-line matches help find
internal overlap. Call-sequence clones, predicate aliases, writer overlap, and state
signals are also already available. They are not general behavioral equivalence proofs
and do not automatically establish replacements by standard libraries or native tools.

The current dataflow matches connect selector decoding and formatting sites, which
were checked against their different contracts. Empty writer-overlap or call-sequence
results do not prove the absence of semantic duplication. Espalier supplies call/state
and complexity clues, but the recorded Go evidence has unresolved calls and lacks runtime
protocol observation.

Request [FR-RC](giga-feature-request.md#fr-rc-replacement-contract-candidates) for bounded,
versioned replacement contracts, and [FR-RP](giga-feature-request.md#fr-rp-resource-protocol-evidence)
for file/process/shell protocol evidence. Extend the existing detectors rather than
requesting dataflow clones or writer overlap again.
