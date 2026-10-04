# Giga feature requests from the unslop architecture audit

Status: requested capabilities, not implemented fixes. These requests are supported by
[type-4-similarities.md](type-4-similarities.md),
[architectural-simplification.md](architectural-simplification.md), and
[architecture-audit.json](../../metrics/data/architecture-audit.json).
Reproduce the source binding and metric records with
`python3 metrics/src/architecture_audit.py`.

## Gap and existing capabilities

Giga's signals were partially sufficient. Espalier and Decomplex located call/state
pressure, complex analysis, selector overlap, and inspection candidates. The recorded
outputs did not provide enough resource-protocol or replacement-contract evidence to
justify a complete architecture replacement. This is a request for auditable leads
and obligations, not an automatic claim that a dependency preserves behavior.

Do not rebuild capabilities Giga already has:

- [F28 dataflow clones](../../../giga/docs/agents/features/f28-dataflow-clones.md)
  matches connected normalized control/data dependence subgraphs, including
  renamed/reordered statements; it is not unrestricted Type-4 equivalence.
- [F29 writer overlap](../../../giga/docs/agents/features/f29-writer-overlap.md)
  tracks proven owned state places and unconnected writers; unresolved owners remain
  outside its proof boundary.
- Decomplex already emits call-sequence clones, aliases, index fan-out, maintained
  aggregates, state heatmaps, implicit protocols, inlined complexity, and an
  attributable-line tally.
- Espalier already projects architecture nodes/edges, pressure, complexity sites,
  hazards, state findings, unresolved call-order metadata, and external/stdlib summaries.
- Giga Core already ingests architecture JSON and stores node/edge metadata with
  focused architecture queries.

The implementation owners below are from inspected source in `~/dev/giga`; source hashes
are recorded under `architecture-audit.json#inspected_external_source_hashes`. They are
implementation pointers, not a claim that current source is the exact build that produced
the archived audit output. The unslop evidence is bound to its recorded checkpoint.

## FR-RP: Resource-protocol evidence

### Concrete missed clue

`ui.RunLive` creates temp files, atomically replaces rows/footer/actions, and launches
fzf with shell bindings that read those files. `ChooseProjectLive` adds preview files
and a shell read. API-level call edges show the ingredients, but not a useful end-to-end
resource path from typed scan result to temporary file to shell consumer to selection.
That path is the main clue that a persistent application is being implemented through
a serialized selector protocol.

### Small useful implementation

Start with resolved Go calls for temp-directory creation, path construction, file
write/rename/read, command launch, and arguments assembled from literals plus known
path fragments. Emit typed resource-use facts at the producer, then join only resource
identities supported by local dataflow. Distinguish read, write, publish/rename, execute,
and cleanup. Preserve the call span and original path-expression evidence.

For fzf bindings, add a bounded recognizer for literal `cat`/reload/preview fragments
and interpolated known resources. Mark this as a recognized command template, not a
fully parsed shell program or proven runtime order. Opaque shell, dynamic filenames,
and unknown commands stay unresolved. Do not infer identity from a basename or match
unrelated `rows` files across scopes. Do not execute commands or read user resources.

Show the resource path, its representations, lifetime owner, and unresolved segments.
This should surface a candidate like "scan snapshot → row bytes → file publication →
fzf shell reload → output token → domain selection" with evidence at each step.
A journal using atomic rename must remain distinct because its durability/recovery
contract differs; no rule should recommend deleting synchronization solely from a path.

### Owners, schema and integration

| File / Symbol | Owner | New State / Mutable Fields | Estimated production LoC |
| --- | --- | --- | ---: |
| `gems/fact-mine/src/syntax/normalized_extractor.rs`, `syntax/cfg/effects.rs` | Giga / FactMine | Per-analysis resolved call arguments and resource-use facts | 120–220 |
| `gems/espalier/src/main.rs`: architecture graph build, `ArchitectureEdge`; `static_evidence.rs` | Giga / Espalier | Per-artifact resource-identity joins; no persistent runtime tracker | 130–230 |
| `gems/gigasail/giga-core/src/db/architecture.rs`, `sql/architecture/load_edges.sql`; focused report path | Giga / Core | Persist evidence metadata in existing artifact storage | 50–100 |

Total estimate: 300–550 production lines and 3–6 engineering days
(metrics/data/architecture-audit.json#giga_feature_plans.resource_protocol,
python3 metrics/src/architecture_audit.py). Component ranges are stored in that record.

Use existing architecture nodes/edges and `metadata_json` for optional evidence fields
where compatible; do not add a second graph store. Suggested metadata: resource kind,
identity basis, operation, call span, argument span, command-template identity, resolution
status, and unknown reasons. If a new mandatory edge kind or payload contract is needed,
version it and update ingest, queries, and readers together. A graph node must have a
deterministic scope-sensitive identity.

Reuse `NodeEffect` and normalized facts rather than adding a parallel extractor. First
check whether those facts preserve command argument values and path definitions; if
they do not, missing producer facts are indispensable work. A complete alias/type system
or general shell interpreter exceeds this estimate and should remain separately unsized.

### Performance, tests and standalone value

Index resources by proven identity and cap candidate groups; avoid all-pairs comparisons
and eager whole-program symbolic execution. Test temp-write/rename/read handoffs, renamed
locals, unrelated same-name resources, unknown arguments, fzf templates, cleanup,
and journal-versus-UI contracts. Round-trip the artifact through Core and a focused query.
Unknown shell paths must appear as unknown, not disappear into a clean result.

The useful standalone result is a queryable resource path even if no architecture
change follows. A recognizer that only prints "many subprocess calls" adds little to
existing call graphs and should be omitted.

## FR-RC: Replacement-contract candidates

### Concrete missed clue

`SanitizeTerminalString` manually performs a transform that `strings.Map` supplies.
`RenderProgressBar` repeats glyphs that `strings.Repeat` supplies. Internal clone
matching cannot prove a replacement by a function outside the repo. Similarly, custom
ancestry traversal suggests native Git, but checkout policy, error behavior, and
performance make replacement conditional.

### Small useful implementation

Add a small versioned set of replacement recipes for the inspected Go idioms. Each
recipe names a canonical API/tool identity, supported source pattern, input assumptions,
preserved outputs/effects, known counterexamples, and remaining proof obligations.
Keep this declarative metadata separate from external complexity bounds; a low complexity
bound is not a behavior contract. Do not attempt to catalog all common dependencies.

Use normalized loop, predicate, and def-use facts to detect candidate slices. F28's
graph machinery is useful for candidate shaping, but matching an API implementation
body does not prove user-code equivalence. Initial candidates should cover the rune
filter and repeated glyph loops; native Git should produce an advisory traversal-owner
lead with explicit safety and performance obligations, not an approved replacement.

For the rune filter, preserve the predicate and malformed UTF-8 behavior. For repetition,
preserve clamping and reject an unproved negative-count contract. For Git, report retained
snapshot/ranking checks, timestamp-order issues, object visibility, tool-version needs,
and subprocess cost. Common TUI libraries can be referenced as inspected options, but
feature parity cannot be established from function names alone.

### Owners, schema and integration

| File / Symbol | Owner | New State / Mutable Fields | Estimated production LoC |
| --- | --- | --- | ---: |
| Replacement-recipe data and catalog gates beside `gems/espalier/src/stdlib_map.rs` summaries | Giga / Espalier or shared catalog owner | Versioned immutable recipes; per-analysis admitted-version status | 60–100 |
| `gems/decomplex/src/decomplex/detectors/dataflow_clone.rs` machinery and `report_facts.rs` integration | Giga / Decomplex | Bounded candidate slices and unresolved obligations | 110–230 |
| `gems/decomplex/src/decomplex/report.rs`, `report_llm.rs` | Giga / Decomplex | Derived JSON/LLM representation | 30–70 |

Total estimate: 200–400 production lines and 3–6 engineering days
(metrics/data/architecture-audit.json#giga_feature_plans.replacement_contracts,
python3 metrics/src/architecture_audit.py). This includes only the bounded useful slice,
not a general behavioral-equivalence solver or a maintained library marketplace.

Emit a candidate with recipe/version, canonical replacement symbol, exact source slice,
matched facts, input-domain status, effects, counterexamples, proof obligations, and
confidence. Separate a proven local obligation from a human-validated complete contract.
No automatic deletion or dependency-install action belongs in this request.

### Performance, tests and standalone value

Prefilter by language and normalized operations; run bounded recipe matches only on
candidate functions. Cache immutable recipe data, not inferred equivalence. Tests must
include valid and malformed UTF-8, changed predicates, width/clamping variants, unrelated
builder loops, and same-named nonstdlib functions. Differential probes can support a
candidate but must record their tested domain and must not be labeled exhaustive proofs.

A complete candidate report independently helps reviewers compare stdlib/native options.
An API suggestion without obligations would repeat the unsupported advice this audit
is intended to prevent.

## FR-EH: Evidence health beside architecture rankings

### Concrete trust problem

The archived corpus is complete for selected files, but contains unresolved call orders
and reports no Go runtime tracing. Some sizeable functions have a zero local-complexity
value in Espalier pressure rows while another analyzer supplies substantial complexity.
The inspected `pressure_rows` also sets the operational component to a placeholder.
These observations do not establish that every zero is a producer bug; they show that
the output needs metric provenance and explicit missingness.

### Small useful implementation

For each owner/callable, expose the available static call, type, effect, closure, and
runtime evidence plus unresolved reasons. Keep selected-file coverage separate from
semantic resolution. Record producer/metric identity and input status for each pressure
component. Use `unknown`, `unsupported`, or `not_collected` for absent inputs rather
than silently treating them as measured zero. A genuine measured zero must remain zero.

The existing corpus capability flags, node metadata, and unresolved-call-order fields
are inputs. Distinguish generic Go capability flags from actually admitted SCIP evidence;
show both instead of collapsing them into a single "complete" badge. Do not make
different complexity metrics share one number merely because their names sound similar.

### Owners, schema and integration

| File / Symbol | Owner | New State / Mutable Fields | Estimated production LoC |
| --- | --- | --- | ---: |
| `gems/espalier/src/main.rs`: `pressure_rows`, numeric defaults and corpus metadata | Giga / Espalier | Derived availability/provenance per component and owner | 50–110 |
| `gems/gigasail/giga-core/sql/architecture/artifact_health.sql`, `db/architecture.rs`, ranking report | Giga / Core | Stored optional metadata; no independent health cache | 30–70 |

Total estimate: 80–180 production lines and 1–3 engineering days
(metrics/data/architecture-audit.json#giga_feature_plans.evidence_health,
python3 metrics/src/architecture_audit.py).

Add optional status/provenance fields first, retaining current readers; a later numeric
schema change requires versioned compatibility work. Link unavailable components to
their reasons without inventing a replacement score. Aggregate already-produced evidence
in one pass instead of rescanning source or executing a second analyzer.

Test measured zero versus missing, unsupported Go runtime evidence, partial call resolution,
closure/interface consumers, old-artifact ingestion, and complete-file/incomplete-effect
cases. Standalone value is an honest explanation of how much a ranking can establish,
even when no further detector is built.

## FR-RB: Complete replacement budget in simplification reports

### Concrete accounting gap

Existing attributable-line reports rank source associated with detector findings.
Those spans can overlap and often contain policy that must move into a replacement.
They do not equal an implemented net deletion. This audit's UI boundary makes that
distinction explicit in the evidence and architecture document.

### Small useful implementation

Extend the existing tally/report path with a separate replacement-budget record. Accept
operator-supplied replacement components and retained responsibilities; record their
estimate provenance. Compute unique candidate source lines from exact matched spans,
keeping uncertain slices separate. Show gross boundary, estimated replacement/adapters,
dependency work, unpriced tests/docs/operations, and net estimated savings. Report actual
diff savings only after a bound replacement patch exists.

Do not manufacture a replacement-size estimate from a detector score. Do not sum
overlapping candidates or count moved code and dependency implementation as deleted
system complexity. Preserve the old attributable tally under its own label.

Support a cumulative portfolio of independent simplifications; do not require a single
large rewrite. Union overlapping source boundaries, flag mutually exclusive alternatives,
and keep measured draft sizes separate from planning ranges and applied patch savings.
Small candidates count when useful, but a deletion target must not turn speculative
upper bounds into validated available savings.

### Owners, schema and integration

| File / Symbol | Owner | New State / Mutable Fields | Estimated production LoC |
| --- | --- | --- | ---: |
| `gems/decomplex/src/decomplex/tally.rs`, `report_facts.rs` | Giga / Decomplex | Per-report unique spans and operator-supplied budget | 50–100 |
| JSON/LLM report integration | Giga / Decomplex | Derived display only | 30–50 |

Total estimate: 80–150 production lines and 1–2 engineering days
(metrics/data/architecture-audit.json#giga_feature_plans.replacement_budget,
python3 metrics/src/architecture_audit.py).

Use sorted interval unions by file, not repeated line expansion across all candidates.
Test overlapping findings, interleaved dataflow slices, retained policy, missing budgets,
negative net savings, code moved between files, and dependency ownership. The standalone
result must also handle cumulative independent candidates and conflicting alternatives.
The standalone
result is bounded savings accounting. An automatic architecture optimizer is out of scope.

## Estimate limits and delivery order

All estimates above are source-informed planning inputs stored in
`metrics/src/architecture_audit.py`, not measured implementation sizes. Production ranges
exclude tests/docs/config; engineering-day ranges include integration, tests, and docs.
They assume the existing normalized argument, span, and identity facts are reusable.
Where that assumption fails, investigate the producer boundary before promising the
consumer feature; a new general indexer, interprocedural symbolic engine, or shell parser
is unsized. No aggregate effort or savings claim is made.

Start with FR-EH so later findings expose their proof boundary, then implement the small
FR-RC recipes. FR-RP is the higher-value architecture clue once argument/resource identity
is confirmed. FR-RB can follow independently where operator-supplied budgets are useful.
Each request must produce a reviewable standalone report without waiting for the others.

Common hazards are false semantic equivalence, conflated resource identity, and misleading
completeness/savings labels. Require source-backed fixture tests and artifact/query
round-trips at the invariant owner. Do not run analyzed shell commands or mutate the
repository as part of detection. Existing Boobytrap/SlopCop integration defects remain
in [giga-hotfix.md](giga-hotfix.md); this document requests new evidence capabilities.

## Why Not Simpler?

- **Delete / omit:** The unslop audit needed evidence that existing call/clone rankings did not provide, so omitting these gaps leaves unsupported replacement claims.
- **Reuse codebase:** Reuse FactMine effects, Decomplex slices/tallies, and Espalier/Core artifacts, extending their proof boundary instead of adding parallel systems.
- **Standard library:** Standard collections and serialization can implement the bounded reports, but they do not supply source-specific contracts or resource identities.
- **Native OS / platform:** Source inspection is sufficient for the proposed static slice, while native command execution would add risk without proving semantic equivalence.
- **Existing dependencies / declarative formats:** Versioned recipes and existing JSON/SQL schemas cover the needed data without a new service or general rule language.
- **Minimal custom code:** Build only the named Go recipes, resolved resource joins, health metadata, and explicit budget calculation, leaving broader equivalence unsized.

## Proposed public/report API changes

| Surface | Change and side effects | Consumer alignment |
| --- | --- | --- |
| FactMine normalized evidence | Add optional resource-use/argument facts with spans and unresolved reasons; pure source analysis. | Espalier projection and fixtures; no competing extractor. |
| Espalier architecture artifact | Add resource/protocol and metric-health metadata with compatible version handling; emits reports only. | Core ingestion, focused queries, architecture reviewers. |
| Decomplex facts/report | Add optional replacement-contract candidates and explicit replacement-budget records. | JSON/LLM readers; old clone/tally fields remain distinct. |
| Core architecture queries | Expose resource paths and metric health from the same stored artifact. | Focused review/MCP consumers; no second graph or health store. |
| Automatic rewrite/install APIs | No addition. | Reviewers validate complete behavior before any separate implementation task. |
