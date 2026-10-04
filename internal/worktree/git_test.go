package worktree

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testGit(t *testing.T, path string, args ...string) string {
	t.Helper()
	output, err := git(path, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(output, "\n")
}

func testRepo(t *testing.T) string {
	t.Helper()
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "Fixture")
	t.Setenv("GIT_AUTHOR_EMAIL", "fixture@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Fixture")
	t.Setenv("GIT_COMMITTER_EMAIL", "fixture@example.com")
	path := t.TempDir()
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	testGit(t, path, "init", "-b", "main")
	testGit(t, path, "config", "commit.gpgsign", "false")
	testGit(t, path, "config", "core.hooksPath", os.DevNull)
	commitFile(t, path, ".gitignore", "ignored/\n", "initial")
	return path
}

func commitFile(t *testing.T, path, name, content, subject string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	testGit(t, path, "add", "--", name)
	testGit(t, path, "commit", "-m", subject)
	return testGit(t, path, "rev-parse", "HEAD")
}

func linked(t *testing.T, primary, branch string) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "linked")
	testGit(t, primary, "worktree", "add", "-b", branch, path)
	return path
}

func findTree(t *testing.T, items []Worktree, path string) Worktree {
	t.Helper()
	for _, item := range items {
		if item.Path == path {
			return item
		}
	}
	t.Fatalf("worktree %q not found: %+v", path, items)
	return Worktree{}
}

func TestGitFailuresStayErrors(t *testing.T) {
	if _, err := analyzeTest(t, t.TempDir()); err == nil {
		t.Fatal("non-repository accepted")
	}
	primary := testRepo(t)
	t.Setenv("PATH", "")
	if _, err := analyzeTest(t, primary); err == nil {
		t.Fatal("missing git accepted")
	}
}

func TestRepositoryListRejectsMissingOrIncompleteEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, script, want string
	}{
		{"missing-common", `if [ "$6" = rev-parse ]; then printf '%s/missing\n' "$3"; exit 0; fi`, "no such file"},
		{"empty-registry", `if [ "$6" = worktree ]; then exit 0; fi`, "no worktrees"},
		{"remote-failure", `if [ "$6" = remote ]; then exit 2; fi`, "git remote"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testRepo(t)
			gitProxy(t, tc.script)
			if _, err := List(root); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("incomplete repository evidence accepted: %v", err)
			}
		})
	}
	t.Run("metadata-removed-during-list", func(t *testing.T) {
		root := testRepo(t)
		gitProxy(t, `if [ "$6" = remote ]; then "$UNSLOP_FIXTURE_GIT" "$@"; /bin/mv "$3/.git" "$3/git-moved"; exit 0; fi`)
		items, err := List(root)
		if err != nil || len(items) != 1 || items[0].Error == "" {
			t.Fatalf("repository without metadata accepted: %+v %v", items, err)
		}
	})
	t.Run("mismatched-checkout-root", func(t *testing.T) {
		root := testRepo(t)
		gitProxy(t, `if [ "$6:$7" = rev-parse:--show-toplevel ]; then printf '%s/.git\n' "$3"; exit 0; fi`)
		items, err := List(root)
		if err != nil || len(items) != 1 || items[0].Error != "checkout is not a valid repository root" {
			t.Fatalf("mismatched repository root accepted: %+v %v", items, err)
		}
	})
}

func TestNulRecordsKeepUnusualPaths(t *testing.T) {
	items := parseWorktrees("worktree /path with space\nnewline\x00HEAD abc\x00branch refs/heads/main\x00\x00worktree /other\x00HEAD def\x00locked reason\x00prunable missing\x00bare\x00\x00")
	if len(items) != 2 || items[0].Path != "/path with space\nnewline" || !items[0].Primary || !items[1].Locked || !items[1].Prunable || !items[1].Bare {
		t.Fatalf("bad NUL records: %+v", items)
	}
}

func TestDiscoveryDeduplicatesAndFindsNestedRepositories(t *testing.T) {
	primary := testRepo(t)
	path := linked(t, primary, "feature")
	nested := filepath.Join(primary, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	testGit(t, nested, "init", "-b", "main")
	commitFile(t, nested, "initial", "nested", "initial")
	linked(t, nested, "nested-feature")
	report := scanTest(t, []string{primary, path, primary}, nil, io.Discard)
	if len(report.Errors) != 0 || len(report.Worktrees) != 4 {
		t.Fatalf("discovery: %+v", report)
	}
	for _, item := range report.Worktrees {
		if item.Path == primary && !item.LocalFiles {
			t.Fatal("nested repository did not protect its containing worktree")
		}
	}
}

func TestDiscoveryErrorsAndMissingRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: missing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := scanTest(t, []string{root, filepath.Join(root, "missing")}, nil, io.Discard)
	if len(report.Errors) != 2 {
		t.Fatalf("missing discovery errors: %+v", report)
	}
}

func TestUnreadableWorktreeIsNotObsolete(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("POSIX permissions")
	}
	primary := testRepo(t)
	path := linked(t, primary, "feature")
	testGit(t, primary, "branch", "retained", "feature")
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0700)
	report := scanTest(t, []string{primary}, nil, io.Discard)
	item := findTree(t, report.Worktrees, path)
	if (!item.Prunable && item.Error == "") || item.Obsolete {
		t.Fatalf("unreadable worktree allowed: %+v", report)
	}
}

func TestDiscoveryDoesNotModifyGitState(t *testing.T) {
	primary := testRepo(t)
	refs := testGit(t, primary, "show-ref")
	index, err := os.Stat(filepath.Join(primary, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	report := scanTest(t, []string{primary}, nil, io.Discard)
	after, err := os.Stat(filepath.Join(primary, ".git", "index"))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 || refs != testGit(t, primary, "show-ref") || !index.ModTime().Equal(after.ModTime()) {
		t.Fatal("scan changed repository state")
	}
}

func TestDiscoveryReadsRegistryWithoutComparingHistory(t *testing.T) {
	defer failOnCrash(t)
	primary := testRepo(t)
	path := linked(t, primary, "feature")
	gitProxy(t, `case "$6" in rev-parse|worktree|remote) ;; *) exit 2;; esac`)
	report := Discover([]string{primary}, nil, io.Discard)
	if len(report.Errors) != 0 || len(report.Worktrees) != 2 {
		t.Fatalf("discovery required history analysis: %+v", report)
	}
	for _, item := range report.Worktrees {
		if item.Status != "unchecked" || item.Obsolete || item.Repository != primary {
			t.Fatalf("registry advertised unverified cleanup evidence: %+v", item)
		}
	}
	findTree(t, report.Worktrees, path)
}

func TestDefaultRoots(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	roots, err := DefaultRoots()
	if err != nil || len(roots) != 1 || roots[0] != home {
		t.Fatalf("roots=%v err=%v", roots, err)
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := DefaultRoots(); err == nil {
		t.Fatal("missing home accepted")
	}
}

func TestGitErrorsIncludeNativeDiagnostics(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	_, err := git(t.TempDir(), "status")
	if err == nil || !strings.Contains(err.Error(), "not a git repository") {
		t.Fatalf("diagnostic lost: %v", err)
	}
}

func gitProxy(t *testing.T, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command fixture")
	}
	native, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := "#!/bin/sh\n" + body + "\nexec \"$UNSLOP_FIXTURE_GIT\" \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UNSLOP_FIXTURE_GIT", native)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRemoteKeysGroupClonesWithoutExposingAuthentication(t *testing.T) {
	defer failOnCrash(t)
	root := testRepo(t)
	for _, tc := range []struct{ address, want string }{
		{"git@GitHub.com:owner/project.git", "github.com/owner/project"},
		{"https://alice:password@github.com/owner/project.git", "github.com/owner/project"},
		{"ssh://git@github.com/owner/project", "github.com/owner/project"},
		{"ssh://git@github.com:2222/owner/project", "github.com:2222/owner/project"},
		{"git@[::1]:owner/project.git", "[::1]/owner/project"},
		{"ssh://git@[::1]/owner/project.git", "[::1]/owner/project"},
		{root, "file:" + root},
		{"file://" + root, "file:" + root},
		{"file://localhost" + root, "file:" + root},
		{"file://server/share/repo", "file://server/share/repo"},
		{"../missing", "file:" + filepath.Join(filepath.Dir(root), "missing")},
	} {
		if key := remoteKey(root, tc.address); key != tc.want {
			t.Errorf("address=%q key=%q want=%q", tc.address, key, tc.want)
		}
	}
	for _, address := range []string{"https://user:password@github.com/owner/project?token=secret", "https://github.com/%invalid", "ext::ssh secret-token host"} {
		key := remoteKey(root, address)
		if key == "" || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "%invalid") {
			t.Fatalf("authentication or invalid address exposed: %q", key)
		}
	}
	if remoteKey(root, "https://host/git?repo=a") == remoteKey(root, "https://host/git?repo=b") {
		t.Fatal("distinct query endpoints combined")
	}
	testGit(t, root, "remote", "add", "origin", "git@github.com:owner/project.git")
	testGit(t, root, "remote", "set-url", "--push", "origin", "git@push-host:separate/project.git")
	testGit(t, root, "remote", "add", "upstream", "https://alice:password@github.com/owner/project.git")
	path := linked(t, root, "feature")
	items, err := List(root)
	if err != nil || len(items) != 2 {
		t.Fatalf("remote inventory: %+v %v", items, err)
	}
	for _, item := range items {
		if len(item.Remotes) != 1 || item.Remotes[0] != "github.com/owner/project" {
			t.Fatalf("remote identity not shared with linked checkout: %+v", item)
		}
	}
	findTree(t, items, path)
}

func TestDiscoveryHandlesFailedRegistryAndPermissions(t *testing.T) {
	t.Run("registry", func(t *testing.T) {
		primary := testRepo(t)
		gitProxy(t, "if [ \"$6\" = worktree ]; then exit 2; fi")
		if report := scanTest(t, nil, []string{primary}, io.Discard); len(report.Errors) == 0 {
			t.Fatal("registry error lost")
		}
	})
	t.Run("verification", func(t *testing.T) {
		primary := testRepo(t)
		gitProxy(t, "if [ \"$6\" = status ]; then exit 2; fi")
		if report := scanTest(t, nil, []string{primary, primary}, io.Discard); len(report.Errors) != 1 || len(report.Worktrees) != 1 {
			t.Fatalf("partial inspection lost or duplicated: %+v", report)
		}
	})
	t.Run("permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Getuid() == 0 {
			t.Skip("POSIX permissions")
		}
		root := t.TempDir()
		restricted := filepath.Join(root, "restricted")
		if err := os.Mkdir(restricted, 0000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(restricted, 0700)
		if report := scanTest(t, []string{root}, nil, io.Discard); len(report.Errors) == 0 {
			t.Fatal("access error lost")
		}
	})
}

func TestDiscoverySkipsDependenciesAndRegisteredCopies(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	primary := testRepo(t)
	path := filepath.Join(root, "linked")
	testGit(t, primary, "worktree", "add", "-b", "feature", path)
	for _, name := range []string{"node_modules", "target", "vendor", ".venv", "venv", ".Trash", ".giga", "standalone"} {
		p := filepath.Join(root, name)
		os.Mkdir(p, 0700)
		testGit(t, p, "init", "-b", "main")
	}
	report := scanTest(t, []string{root}, []string{primary}, io.Discard)
	if len(report.Errors) != 0 || len(report.Worktrees) != 3 {
		t.Fatalf("generated directories polluted discovery: %+v", report)
	}
	if item := findTree(t, report.Worktrees, filepath.Join(root, "standalone")); !item.Primary || item.Obsolete {
		t.Fatalf("standalone repository missing or unsafe: %+v", item)
	}
	report = scanTest(t, []string{filepath.Join(root, "target")}, nil, io.Discard)
	if len(report.Errors) != 0 || len(report.Worktrees) != 1 {
		t.Fatalf("explicit build-folder root skipped: %+v", report)
	}
}

func failOnCrash(t *testing.T) {
	t.Helper()
	if crash := recover(); crash != nil {
		t.Fatalf("worktree analysis crashed: %v", crash)
	}
}

func analyzeTest(t *testing.T, path string) ([]Worktree, error) {
	t.Helper()
	defer failOnCrash(t)
	return List(path)
}

func scanTest(t *testing.T, roots, repositories []string, progress io.Writer) Report {
	t.Helper()
	defer failOnCrash(t)
	report := Discover(roots, repositories, progress)
	var items []Worktree
	for _, group := range Groups(report.Worktrees) {
		project := AnalyzeProject(context.Background(), group, 14)
		report.Errors = append(report.Errors, project.Errors...)
		items = append(items, project.Worktrees...)
	}
	report.Worktrees = items
	return report
}

func git(path string, args ...string) (string, error) {
	return gitContext(context.Background(), path, args...)
}
