package worktree

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBranchHistoryKeepsOldAncestryAndStopsOnIncompleteOrCancelledWork(t *testing.T) {
	graph := map[string]historyNode{
		"merged": {parents: []string{"active", "old"}, timestamp: 30},
		"active": {parents: []string{"root"}, timestamp: 20},
		"old":    {parents: []string{"root"}, timestamp: 5},
		"root":   {timestamp: 1},
	}
	heads := map[string]bool{"merged": true, "active": true, "old": true}
	contains, recent, err := branchHistory(context.Background(), graph, heads, 10)
	if err != nil || !contains["merged"]["old"] || !contains["merged"]["active"] || contains["active"]["old"] || len(recent["merged"]) != 2 || len(recent["old"]) != 0 {
		t.Fatalf("old ancestry or recent work lost: %v %v %v", contains, recent, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := branchHistory(ctx, graph, heads, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled traversal continued: %v", err)
	}
	delete(graph, "root")
	if _, _, err := branchHistory(context.Background(), graph, heads, 10); err == nil || !strings.Contains(err.Error(), "incomplete history") {
		t.Fatalf("missing parent accepted as retained history: %v", err)
	}
}

func projectFixture(t *testing.T) (string, string) {
	t.Helper()
	primary := testRepo(t)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(parent, "giga")
	if err := os.Rename(primary, base); err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(parent, "giga-agent")
	testGit(t, base, "clone", "--no-local", base, copy)
	testGit(t, base, "remote", "add", "origin", "https://example.com/giga.git")
	testGit(t, copy, "remote", "set-url", "origin", "git@example.com:giga.git")
	return base, copy
}

func projectFor(t *testing.T, paths ...string) Project {
	t.Helper()
	var items []Worktree
	for _, path := range paths {
		trees, err := List(path)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, trees...)
	}
	project := AnalyzeProject(context.Background(), items, 14)
	if len(project.Errors) > 0 {
		t.Fatal(project.Errors)
	}
	return project
}

func branchFor(t *testing.T, project Project, repo, name string) Branch {
	t.Helper()
	for _, branch := range project.Branches {
		if branch.Repository == repo && branch.Name == "refs/heads/"+name {
			return branch
		}
	}
	t.Fatalf("branch %s missing", name)
	return Branch{}
}

func TestCloneCandidateRequiresEveryBranchRetained(t *testing.T) {
	base, copy := projectFixture(t)
	if !findTree(t, projectFor(t, base, copy).Worktrees, copy).Obsolete {
		t.Fatal("identical clean clone was not a candidate")
	}
	testGit(t, copy, "checkout", "-b", "forgotten")
	hash := commitFile(t, copy, "work.txt", "important", "recover forgotten branch")
	testGit(t, copy, "checkout", "main")
	if _, err := git(base, "cat-file", "-e", hash); err == nil {
		t.Fatal("fixture shared new objects")
	}
	project := projectFor(t, base, copy)
	if project.MainRepository != base || findTree(t, project.Worktrees, copy).Obsolete {
		t.Fatalf("unmerged branch incorrectly retired: %+v", project)
	}
	branch := branchFor(t, project, copy, "forgotten")
	if branch.CheckedOut || !branch.LocalOnly || len(branch.Commits) != 1 || branch.Commits[0].Hash != hash {
		t.Fatalf("forgotten branch work missing: %+v", branch)
	}
	testGit(t, base, "fetch", copy, "forgotten")
	testGit(t, base, "merge", "--no-ff", "FETCH_HEAD", "-m", "integrate forgotten work")
	project = projectFor(t, base, copy)
	if !findTree(t, project.Worktrees, copy).Obsolete {
		t.Fatal("fully retained clone not identified")
	}
	if findTree(t, project.Worktrees, base).Obsolete {
		t.Fatal("canonical repository retired")
	}
}

func TestOldUniqueWorkPreventsCleanupDespiteWindow(t *testing.T) {
	base, copy := projectFixture(t)
	testGit(t, copy, "checkout", "-b", "old-work")
	t.Setenv("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
	t.Setenv("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
	commitFile(t, copy, "old.txt", "valuable", "old distinct work")
	testGit(t, copy, "checkout", "main")
	project := projectFor(t, base, copy)
	if findTree(t, project.Worktrees, copy).Obsolete {
		t.Fatal("old unmerged work marked safe")
	}
	if len(branchFor(t, project, copy, "old-work").Commits) != 0 {
		t.Fatal("date window ignored")
	}
}

func TestPatchEquivalentCloneIsNotFullyMerged(t *testing.T) {
	base, copy := projectFixture(t)
	testGit(t, copy, "checkout", "-b", "feature")
	hash := commitFile(t, copy, "feature.txt", "feature", "feature patch")
	testGit(t, base, "fetch", copy, "feature")
	commitFile(t, base, "base.txt", "base", "advance original")
	testGit(t, base, "cherry-pick", hash)
	project := projectFor(t, base, copy)
	if findTree(t, project.Worktrees, copy).Obsolete {
		t.Fatal("cherry pick counted as full merge")
	}
}

func TestLinkedCopiesRequireRetainedHistoryAndCleanState(t *testing.T) {
	for _, kind := range []string{"clean", "dirty", "untracked", "ignored", "locked", "detached", "unmerged"} {
		t.Run(kind, func(t *testing.T) {
			base := testRepo(t)
			path := linked(t, base, "feature")
			commitFile(t, path, "feature.txt", "feature", "feature work")
			if kind != "unmerged" {
				testGit(t, base, "merge", "--no-ff", "feature", "-m", "integrate")
			}
			switch kind {
			case "dirty":
				os.WriteFile(filepath.Join(path, "feature.txt"), []byte("unfinished"), 0600)
			case "untracked":
				os.WriteFile(filepath.Join(path, "notes"), []byte("notes"), 0600)
			case "ignored":
				os.Mkdir(filepath.Join(path, "ignored"), 0700)
				os.WriteFile(filepath.Join(path, "ignored", "notes"), []byte("notes"), 0600)
			case "locked":
				testGit(t, base, "worktree", "lock", path)
			case "detached":
				testGit(t, path, "checkout", "--detach")
			}
			project := projectFor(t, base)
			if findTree(t, project.Worktrees, path).Obsolete != (kind == "clean" || kind == "detached") {
				t.Fatalf("wrong cleanup decision: %+v", project.Worktrees)
			}
		})
	}
}

func TestMainBranchPrefersIntegrationOverFreshSideBranch(t *testing.T) {
	base := testRepo(t)
	path := linked(t, base, "active-feature")
	commitFile(t, path, "feature.txt", "feature", "feature")
	testGit(t, base, "merge", "--no-ff", "active-feature", "-m", "integrated")
	testGit(t, base, "branch", "integrated-tip")
	testGit(t, base, "checkout", "-b", "new-side", "main~1")
	commitFile(t, base, "side.txt", "side", "new recent side work")
	project := projectFor(t, base)
	if project.MainBranch != "refs/heads/integrated-tip" && project.MainBranch != "refs/heads/main" {
		t.Fatalf("integration history lost to a fresh checkout: %s", project.MainBranch)
	}
}

func TestCanonicalRootBeatsCopiesWithMoreRecentWork(t *testing.T) {
	base, copy := projectFixture(t)
	commitFile(t, copy, "new.txt", "agent work", "fresh agent work")
	if project := projectFor(t, copy, base); project.MainRepository != base {
		t.Fatalf("agent copy won: %s", project.MainRepository)
	}
}

func TestProjectReportListsAliasesAndSanitizesTerminalText(t *testing.T) {
	var output bytes.Buffer
	project := Project{Days: 14, MainRepository: "/repo", MainBranch: "refs/heads/main", Branches: []Branch{
		{Name: "refs/heads/main", Repository: "/repo", Head: "abc", Commits: []Commit{{Hash: "abc", Subject: "fix\x1b"}}},
		{Name: "refs/heads/alias", Repository: "/copy", Head: "abc", Commits: []Commit{{Hash: "abc", Subject: "fix\x1b"}}},
	}, Errors: []string{"bad\x1bmetadata"}}
	PrintProject(project, &output)
	if strings.ContainsRune(output.String(), '\x1b') || strings.Count(output.String(), "abc fix") != 1 || !strings.Contains(output.String(), "Same tip") || !strings.Contains(output.String(), "incomplete") {
		t.Fatal(output.String())
	}
}

func TestStashedWorkProtectsAnOtherwiseMergedClone(t *testing.T) {
	base, copy := projectFixture(t)
	if err := os.WriteFile(filepath.Join(copy, "unfinished"), []byte("work"), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, copy, "stash", "push", "-u", "-m", "unfinished work")
	if item := findTree(t, projectFor(t, base, copy).Worktrees, copy); item.Obsolete {
		t.Fatal("stashed work was marked disposable")
	}
}

func TestGitInspectionIgnoresCallerRepositoryEnvironment(t *testing.T) {
	base := testRepo(t)
	t.Setenv("GIT_DIR", filepath.Join(base, "missing"))
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	if items, err := List(base); err != nil || len(items) != 1 || items[0].Error != "" {
		t.Fatalf("caller environment redirected repository inspection: %+v %v", items, err)
	}
}

func TestChangedOriginDoesNotAuthorizeCloneCleanup(t *testing.T) {
	base, copy := projectFixture(t)
	a, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := List(copy)
	if err != nil {
		t.Fatal(err)
	}
	testGit(t, copy, "remote", "set-url", "origin", "https://example.com/other.git")
	project := AnalyzeProject(context.Background(), append(a, b...), 14)
	if len(project.Errors) == 0 {
		t.Fatal("changed origin accepted")
	}
	for _, item := range project.Worktrees {
		if item.Obsolete {
			t.Fatal("unrelated repository retired")
		}
	}
}

func TestProjectFailuresStayVisibleAndPreventCleanup(t *testing.T) {
	for _, stage := range []string{"worktree", "count-objects", "shallow-check", "objects", "refs", "log", "timestamp", "history", "status", "head", "changed-refs", "cancelled"} {
		t.Run(stage, func(t *testing.T) {
			base, copy := projectFixture(t)
			a, err := List(base)
			if err != nil {
				t.Fatal(err)
			}
			b, err := List(copy)
			if err != nil {
				t.Fatal(err)
			}
			head := testGit(t, base, "rev-parse", "HEAD")
			t.Setenv("UNSLOP_PROJECT_HEAD", head)
			t.Setenv("UNSLOP_PROJECT_COPY", copy)
			body := ""
			switch stage {
			case "shallow-check":
				body = `if [ "$6:$7" = rev-parse:--is-shallow-repository ]; then exit 2; fi`
			case "objects":
				body = `if [ "$6:$9" = rev-parse:objects ]; then exit 2; fi`
			case "refs":
				body = `if [ "$6" = for-each-ref ]; then exit 2; fi`
			case "timestamp":
				body = `if [ "$6" = log ]; then printf '%s\t\tbad\tbad timestamp\n' "$UNSLOP_PROJECT_HEAD"; exit 0; fi`
			case "history":
				body = `if [ "$6" = log ]; then printf '%s\tmissing-parent\t1\tincomplete history\n' "$UNSLOP_PROJECT_HEAD"; exit 0; fi`
			case "head":
				body = `if [ "$6:$7" = rev-parse:HEAD ]; then printf 'changed\n'; exit 0; fi`
			case "changed-refs":
				body = `if [ "$6" = log ]; then "$UNSLOP_FIXTURE_GIT" -C "$UNSLOP_PROJECT_COPY" branch discovered-during-scan; fi`
			case "cancelled":
			default:
				body = `if [ "$6" = ` + stage + ` ]; then exit 2; fi`
			}
			if body != "" {
				gitProxy(t, body)
			}
			ctx := context.Background()
			if stage == "cancelled" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			project := AnalyzeProject(ctx, append(a, b...), 14)
			if len(project.Errors) == 0 {
				t.Fatal("verification failure hidden")
			}
			for _, item := range project.Worktrees {
				if item.Obsolete {
					t.Fatalf("cleanup allowed on %s failure", stage)
				}
			}
		})
	}
}

func TestProjectWithMissingCheckoutIsNotSafe(t *testing.T) {
	base := testRepo(t)
	path := linked(t, base, "gone")
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	items, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	project := AnalyzeProject(context.Background(), items, 14)
	if len(project.Errors) == 0 {
		t.Fatal("missing checkout check was hidden")
	}
	for _, item := range project.Worktrees {
		if item.Obsolete {
			t.Fatal("incomplete inventory marked safe")
		}
	}
}

func TestCanonicalRepositoryRanking(t *testing.T) {
	for _, tc := range []struct {
		items []Worktree
		want  string
	}{
		{nil, ""},
		{[]Worktree{{Repository: "/a/x", Primary: true}, {Repository: "/b/y", Primary: true}}, "/a/x"},
		{[]Worktree{{Repository: "/a/long", Primary: true}, {Repository: "/b/x", Primary: true}}, "/b/x"},
		{[]Worktree{{Repository: "/a/x", Primary: true}, {Repository: "/b/y", Primary: true}, {Repository: "/b/y", Path: "/b/y-linked"}}, "/b/y"},
		{[]Worktree{{Repository: "/a/giga-x", Primary: true}, {Repository: "/a/giga", Primary: true}}, "/a/giga"},
	} {
		if got := canonicalRepository(tc.items); got != tc.want {
			t.Fatalf("canonical=%s want=%s", got, tc.want)
		}
	}
}

func TestMainBranchTieBreakers(t *testing.T) {
	contains := map[string]map[string]bool{"left": {"left": true}, "right": {"right": true}}
	for _, tc := range []struct{ left, right Branch }{
		{Branch{PrimaryCheckout: true}, Branch{Recent: 100}},
		{Branch{Recent: 2}, Branch{Recent: 1}},
		{Branch{CheckedOut: true}, Branch{}},
		{Branch{LocalOnly: true}, Branch{}},
		{Branch{LastCommit: 2}, Branch{LastCommit: 1}},
		{Branch{Name: "a"}, Branch{Name: "b"}},
	} {
		tc.left.Head = "left"
		tc.right.Head = "right"
		if !betterBranch(tc.left, tc.right, contains) || betterBranch(tc.right, tc.left, contains) {
			t.Fatalf("wrong branch ordering: %+v", tc)
		}
	}
}

func TestEmptyAndBareProjectsRemainProtected(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	testGit(t, base, "init", "-b", "main")
	project := projectFor(t, base)
	if len(project.Branches) != 0 || findTree(t, project.Worktrees, base).Obsolete {
		t.Fatal("unborn repository marked safe")
	}
	primary := testRepo(t)
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(parent, "bare")
	testGit(t, primary, "clone", "--bare", primary, bare)
	project = projectFor(t, bare)
	if project.MainBranch != "refs/heads/main" || findTree(t, project.Worktrees, bare).Obsolete {
		t.Fatal("bare repository lost protection")
	}
}

func TestRegistryCannotClaimAReplacementRepository(t *testing.T) {
	base := testRepo(t)
	path := linked(t, base, "old")
	if err := os.Remove(filepath.Join(path, ".git")); err != nil {
		t.Fatal(err)
	}
	testGit(t, path, "init", "-b", "main")
	items, err := List(base)
	if err != nil {
		t.Fatal(err)
	}
	if findTree(t, items, path).Error == "" {
		t.Fatal("replacement repository mistaken for a linked checkout")
	}
}

func TestListRejectsStaleRegisteredCheckout(t *testing.T) {
	primary := testRepo(t)
	path := linked(t, primary, "gone")
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	items, err := List(primary)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.Path == path && item.Error == "" {
			t.Fatal("missing checkout surfaced as a repository")
		}
	}
}

func TestRepositoryRowsExcludeStandaloneAndInvalidRepos(t *testing.T) {
	items := []Worktree{{Repository: "/solo", Path: "/solo", Primary: true},
		{Repository: "/broken", Path: "/broken", Primary: true, Error: "not a repository"}}
	rows, _ := repositoryRows(items)
	if rows.Len() != 0 {
		t.Fatalf("non-duplicates surfaced: %q", rows.String())
	}
}

func TestOriginDoesNotGroupUnrelatedForks(t *testing.T) {
	first, second := testRepo(t), testRepo(t)
	for _, path := range []string{first, second} {
		testGit(t, path, "remote", "add", "upstream", "https://example.com/shared.git")
	}
	testGit(t, first, "remote", "add", "origin", "https://example.com/first.git")
	testGit(t, second, "remote", "add", "origin", "https://example.com/second.git")
	a, err := List(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := List(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(Groups(append(a, b...))) != 2 {
		t.Fatal("shared upstream grouped different origins")
	}
}

func TestListDoesNotMistakeParentRepoForRegisteredPath(t *testing.T) {
	primary := testRepo(t)
	path := linked(t, primary, "broken")
	if err := os.Remove(filepath.Join(path, ".git")); err != nil {
		t.Fatal(err)
	}
	items, err := List(primary)
	if err != nil {
		t.Fatal(err)
	}
	if item := findTree(t, items, path); item.Error == "" {
		t.Fatal("invalid git marker accepted")
	}
}

func TestDuplicateRowsDoNotClaimUncheckedCopiesAreSafe(t *testing.T) {
	items := []Worktree{{Repository: "/repo", Path: "/repo", Primary: true, Status: "unchecked"}, {Repository: "/repo", Path: "/repo-old", Status: "unchecked"}}
	rows, _ := repositoryRows(items)
	if !strings.Contains(rows.String(), "Enter") || strings.Contains(rows.String(), "safe: 1") {
		t.Fatalf("bad unchecked row: %q", rows.String())
	}
}

func TestShallowCanonicalCannotRetainFullCloneHistory(t *testing.T) {
	base, copy := projectFixture(t)
	hash := commitFile(t, copy, "second.txt", "second", "second commit")
	testGit(t, copy, "update-ref", "refs/remotes/origin/main", hash)
	origin := filepath.Join(t.TempDir(), "source")
	if err := os.Rename(copy, origin); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	testGit(t, origin, "clone", "--depth=1", "--no-local", origin, base)
	testGit(t, base, "remote", "set-url", "origin", "https://example.com/giga.git")
	if err := os.Rename(origin, copy); err != nil {
		t.Fatal(err)
	}
	var items []Worktree
	for _, path := range []string{base, copy} {
		trees, err := List(path)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, trees...)
	}
	project := AnalyzeProject(context.Background(), items, 14)
	if findTree(t, project.Worktrees, copy).Obsolete || len(project.Errors) == 0 {
		t.Fatalf("shallow canonical advertised full history retention: %+v", project)
	}
}

func TestCanonicalSharedCloneCannotRetireItsObjectStore(t *testing.T) {
	base, copy := projectFixture(t)
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	testGit(t, copy, "clone", "--shared", copy, base)
	testGit(t, base, "remote", "set-url", "origin", "https://example.com/giga.git")
	var items []Worktree
	for _, path := range []string{base, copy} {
		trees, err := List(path)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, trees...)
	}
	project := AnalyzeProject(context.Background(), items, 14)
	if findTree(t, project.Worktrees, copy).Obsolete {
		t.Fatal("canonical clone still borrows objects from the cleanup candidate")
	}
}
