"""Bind architecture proposals to source; estimates are inputs, not measurements."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'metrics/data'


def read(name):
    return json.loads((DATA / name).read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


probe = json.loads(subprocess.check_output(
    ['go', 'run', str(ROOT / 'metrics/src/architecture_probe.go'), str(ROOT)], cwd=ROOT))
assert all(row['mismatches'] == 0 for row in probe['stdlib_probes'].values()), 'Stdlib draft changed tested behavior'
(DATA / 'architecture-probe.json').write_text(json.dumps(probe, indent=2) + '\n')
shape = json.loads(subprocess.check_output(
    ['go', 'run', str(ROOT / 'metrics/src/debt_shape.go'), str(ROOT)], cwd=ROOT))
snapshot = read('hunt-round-m-snapshot.json')
hashes = {path: digest(ROOT / path) for path in shape}
assert all(snapshot['files'][path] == value for path, value in hashes.items()), 'Production changed since Giga evidence'
architecture = read('hunt-round-m-espalier-architecture.json')
assert architecture['corpus']['commit'] == snapshot['revision'], 'Stale architecture artifact'
decomplex = read('hunt-round-m-decomplex.json')
nodes = {node['id']: node for node in architecture['nodes']}


def component(name, low, high, basis):
    return {'name': name, 'new_production_lines': [low, high], 'basis': basis}


def proposal(symbols, components):
    spans = {key: probe['declarations'][key] for key in symbols}
    old = sum(span['lines'] for span in spans.values())
    low = sum(c['new_production_lines'][0] for c in components)
    high = sum(c['new_production_lines'][1] for c in components)
    return {'removed_symbol_spans': spans, 'measured_gross_lines': old,
            'replacement_components': components, 'estimated_replacement_lines': [low, high],
            'estimated_net_removed_lines': [old-high, old-low],
            'status': 'Unimplemented planning estimate; includes retained responsibilities within replaced symbols. Imports, tests, docs and dependency source excluded. Not additive with other proposals.'}


ui_symbols = {
    'internal/ui/live.go': ['LiveUpdate', 'RunLive', 'ChooseFilesLive'],
    'internal/ui/ui.go': ['fileRows', 'fileSelector', 'selectedFiles', 'SelectionTokens'],
    'internal/worktree/ui.go': ['repositoryRows', 'selectorCommand', 'selectedOutput'],
    'internal/worktree/live.go': ['progressFooter', 'ChooseLive', 'ChooseProjectLive', 'projectRows'],
    'internal/repo/ui.go': ['RunRepoUI'],
}
plans = {
    'typed_ui': proposal([f'{path}:{symbol}' for path, symbols in ui_symbols.items() for symbol in symbols], [
        component('Event owner, scan delivery, cancellation and terminal lifetime', 65, 100,
                  'RunLive producer/wait joins; ChooseLive and ChooseFilesLive callbacks; Bubble Tea Program.Send/WithContext APIs'),
        component('Fuzzy list, selection identities, multi-select, key bindings and tab/detail navigation', 90, 140,
                  'Bubbles list owns fuzzy filtering, but Files/history multi-select and f/r navigation remain application policy'),
        component('Files, duplicate groups, branches, previews, errors and progress rendering', 100, 160,
                  'fileRows/repositoryRows/projectRows/progressFooter retain different domain information; no generic domain framework'),
        component('CLI integration and retained history noninteractive fallback', 35, 60,
                  'RunRepoUI includes stdout fallback; cmd/unslop main/worktrees/repo need wiring; policy helpers stay'),
    ]),
    'native_git': proposal(['internal/worktree/projects.go:'+symbol for symbol in ['historyNode', 'AnalyzeProject', 'branchHistory']], [
        component('Retained snapshot, object pooling, grouping, ranking, safety and ref revalidation', 185, 220,
                  'AnalyzeProject pre-history acquisition and post-ranking checkout/ref checks remain mandatory'),
        component('Native Git ancestry/recent-log queries, decoding, cancellation and failures', 45, 70,
                  'Replace historyNode/branchHistory with merge-base and log; head containment map still feeds betterBranch'),
    ]),
    'single_inspection': proposal(['internal/scanner/scanner.go:InspectSubtree',
                                  'internal/platform/platform.go:ContainsProtectedPath',
                                  'internal/platform/platform.go:ContainsMountOrReparsePoint'], [
        component('Shared inspection with protection, metadata, times, devices and failure/early-exit policies', 90, 130,
                  'Existing walkers differ in early exit, metadata, cancellation, device identity, root and symlink handling'),
        component('Scan/execution adapters and platform device access', 20, 40,
                  'Fresh execution inspection must remain; scanner imports platform so platform cannot import scanner'),
    ]),
}
plans['typed_ui']['recommendation'] = 'Reject the rewrite on current evidence: estimated savings are small and no user/performance benefit has been demonstrated.'
stdlib = {}
for name, old_symbol, draft_symbol in [
        ('terminal_filter', 'internal/ui/ui.go:SanitizeTerminalString', 'sanitizeWithMap'),
        ('progress_bar', 'internal/ui/ui.go:RenderProgressBar', 'progressWithRepeat')]:
    old = probe['declarations'][old_symbol]
    draft = probe['draft_spans'][draft_symbol]
    stdlib[name] = {'existing_symbol': old_symbol, 'existing_span': old,
                    'draft_symbol': draft_symbol, 'draft_span': draft,
                    'draft_source': 'metrics/src/architecture_probe.go',
                    'measured_existing_lines': old['lines'], 'measured_draft_lines': draft['lines'],
                    'measured_draft_net_removed_lines': old['lines'] - draft['lines'],
                    'status': 'Measured research draft, not applied production deletion; equivalence limited to recorded probes and inspected contracts.'}
stdlib_totals = {key: sum(item[key] for item in stdlib.values()) for key in
                 ['measured_existing_lines', 'measured_draft_lines', 'measured_draft_net_removed_lines']}
aggregate = {'included': ['stdlib_drafts', 'native_git', 'single_inspection'], 'excluded': ['typed_ui'],
             'estimated_net_removed_lines': [stdlib_totals['measured_draft_net_removed_lines'] +
                                            sum(plans[name]['estimated_net_removed_lines'][i] for name in ['native_git', 'single_inspection'])
                                            for i in [0, 1]],
             'status': 'Cumulative planning arithmetic over disjoint source boundaries; unproved parity/performance, not safely available deletions. UI rewrite rejected. No savings credited to unsized leads.'}
unsized_leads = {
    'selection_decoding': {'symbols': ['internal/ui/ui.go:selectedFiles', 'internal/worktree/ui.go:selectedOutput', 'internal/repo/ui.go:RunRepoUI'],
                           'status': 'Shared decoding already exists; remaining cancellation/eligibility contracts differ. No smaller complete equivalent was demonstrated.'},
    'executable_classification': {'symbols': ['internal/scanner/scanner.go:IsExecutableBinary'],
                                'status': 'MIME/native-parser substitution rejected because policy and malformed-file behavior differ.'},
    'linux_trash': {'symbols': ['internal/executor/executor.go:moveToTrash', 'internal/executor/executor.go:findUniqueTrashDest', 'internal/executor/executor.go:createTrashInfo', 'internal/platform/platform_linux.go:MoveToTrashOS'],
                    'status': 'Fallback and utility paths are required for different runtime availability; no equivalent dependency replacement demonstrated.'},
}

feature_plans = {
    'resource_protocol': {
        'components': [component('Go call/argument effect summaries', 120, 220, 'FactMine normalized_extractor.rs, syntax/cfg/effects.rs; resolved API identity required'),
                       component('Espalier resource identity joins and protocol candidate projection', 130, 230, 'main.rs ArchitectureEdge/graph build; static_evidence.rs'),
                       component('Artifact/DB query/report wiring', 50, 100, 'architecture metadata_json exists; db/architecture.rs and load_edges.sql')],
        'engineering_days': [3, 6],
    },
    'replacement_contracts': {
        'components': [component('Versioned Go recipe contracts and catalog/source gates', 60, 100, 'Espalier stdlib_map.rs already supplies external summaries; keep replacement recipes separate from cost bounds'),
                       component('Bounded idiom matching and obligation/counterexample report', 110, 230, 'Decomplex dataflow_clone.rs/report_facts.rs; initial Map, Repeat, native Git candidates'),
                       component('JSON/LLM report wiring', 30, 70, 'Decomplex report_llm.rs/report.rs')],
        'engineering_days': [3, 6],
    },
    'evidence_health': {
        'components': [component('Metric provenance and per-owner call/type/effect completeness', 50, 110, 'Espalier pressure_rows and float; existing corpus capability fields'),
                       component('Health query and report display', 30, 70, 'giga-core sql/architecture/artifact_health.sql and db/architecture.rs')],
        'engineering_days': [1, 3],
    },
    'replacement_budget': {
        'components': [component('Unique-span accounting and operator-supplied replacement budget', 50, 100, 'Decomplex tally.rs/report_facts.rs already contain attributable span accounting'),
                       component('JSON/LLM integration', 30, 50, 'Report gross candidates separately from net planned savings')],
        'engineering_days': [1, 2],
    },
}
for plan in feature_plans.values():
    plan['estimated_production_lines'] = [sum(c['new_production_lines'][i] for c in plan['components']) for i in [0, 1]]
    plan['estimate_status'] = 'Source-informed estimate for a Go-only useful slice including integration. Days include tests/docs; discovery of missing type/argument facts can exceed this range. Broad multilingual equivalence and a complete new semantic indexer are unsized.'

external_paths = [
    Path('/Users/cuzzo/dev/giga/gems/espalier/src/main.rs'),
    Path('/Users/cuzzo/dev/giga/gems/espalier/src/static_evidence.rs'),
    Path('/Users/cuzzo/dev/giga/gems/espalier/src/stdlib_map.rs'),
    Path('/Users/cuzzo/dev/giga/gems/decomplex/src/decomplex/detectors/dataflow_clone.rs'),
    Path('/Users/cuzzo/dev/giga/gems/decomplex/src/decomplex/detectors/writer_overlap.rs'),
    Path('/Users/cuzzo/dev/giga/gems/gigasail/giga-core/src/db/architecture.rs'),
    Path('/Users/cuzzo/go/pkg/mod/github.com/charmbracelet/bubbletea@v0.23.0/tea.go'),
    Path('/Users/cuzzo/go/pkg/mod/github.com/charmbracelet/bubbletea@v0.23.0/options.go'),
    Path('/Users/cuzzo/go/pkg/mod/github.com/charmbracelet/bubbles@v0.14.0/list/list.go'),
    Path('/Users/cuzzo/go/pkg/mod/github.com/rivo/tview@v0.0.0-20221029100920-c4a7e501810d/application.go'),
    Path('/Users/cuzzo/go/pkg/mod/github.com/sahilm/fuzzy@v0.1.0/fuzzy.go'),
    Path('/Users/cuzzo/dev/devil/docs/agents/giga-superfluous-state-request-2.md'),
]
result = {
    'source_revision': snapshot['revision'], 'root_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
    'scope': 'Production Go declarations count physical inclusive AST spans, including internal blank/comment lines. Does not count library implementation as eliminated complexity.',
    'production_hashes': hashes, 'all_production_matches_giga_snapshot': True,
    'evidence_hashes': {name: digest(DATA/name) for name in ['hunt-round-m-espalier-architecture.json', 'hunt-round-m-decomplex.json']},
    'production_totals': {key: sum(row[key] for row in shape.values()) for key in ['lines', 'functions', 'decision_sites', 'tokens', 'ast_nodes']},
    'stdlib_probes': probe['stdlib_probes'], 'stdlib_draft_sizes': stdlib, 'stdlib_draft_totals': stdlib_totals,
    'plans': plans, 'cumulative_type4_plan': aggregate, 'unsized_type4_leads': unsized_leads,
    'giga_feature_plans': feature_plans,
    'giga': {'corpus': architecture['corpus'],
             'edge_kind_counts': {kind: sum(edge['kind']==kind for edge in architecture['edges']) for kind in sorted({edge['kind'] for edge in architecture['edges']})},
             'pressure': [{'path': nodes[row['node_id']].get('path'), 'name': nodes[row['node_id']].get('name'), **row} for row in architecture['pressure']],
             'architecture_detector_outputs': {key: decomplex['detectors'].get(key) for key in ['dataflow_clone', 'call_sequence_clone', 'writer_overlap', 'semantic_alias', 'function_lcom', 'operational_discontinuity', 'index_fanout', 'state_heatmap', 'weighted_inlined_complexity']},
             'operational_component_is_placeholder': True,
             'operational_component_basis': 'Espalier main.rs pressure_rows sets operational: 0.0; it is not a runtime operational-cost observation'},
    'inspected_external_source_hashes': {str(path): digest(path) for path in external_paths},
    'new_production_deletions_applied': 0,
}
(DATA / 'architecture-audit.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: {k: plan[k] for k in ['measured_gross_lines', 'estimated_replacement_lines', 'estimated_net_removed_lines']} for key, plan in plans.items()}, indent=2))
