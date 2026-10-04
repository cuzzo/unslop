package worktree

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yahn/unslop/internal/ui"
)

type Branch struct {
	Repository      string   `json:"repository"`
	Name            string   `json:"name"`
	Head            string   `json:"head"`
	CheckedOut      bool     `json:"checked_out"`
	PrimaryCheckout bool     `json:"primary_checkout"`
	LocalOnly       bool     `json:"local_only"`
	Recent          int      `json:"recent_commits"`
	LastCommit      int64    `json:"last_commit"`
	Commits         []Commit `json:"distinct_recent_commits"`
}

type Project struct {
	MainRepository string     `json:"main_repository"`
	MainBranch     string     `json:"main_branch"`
	Days           int        `json:"days"`
	Worktrees      []Worktree `json:"worktrees"`
	Branches       []Branch   `json:"branches"`
	Errors         []string   `json:"errors"`
}

func canonicalRepository(items []Worktree) string {
	best, bestCopies, bestTrees := "", -1, -1
	for _, item := range items {
		if !item.Primary || item.Error != "" {
			continue
		}
		copies, trees := 0, 0
		for _, other := range items {
			if other.Primary && other.Error == "" && strings.HasPrefix(filepath.Base(other.Repository), filepath.Base(item.Repository)+"-") {
				copies++
			}
			if other.Repository == item.Repository && !other.Primary && other.Error == "" {
				trees++
			}
		}
		if copies < bestCopies || (copies == bestCopies && trees < bestTrees) {
			continue
		}
		if copies == bestCopies && trees == bestTrees && (len(item.Repository) > len(best) || (len(item.Repository) == len(best) && item.Repository >= best)) {
			continue
		}
		best, bestCopies, bestTrees = item.Repository, copies, trees
	}
	return best
}

type historyNode struct {
	parents   []string
	timestamp int64
	subject   string
}

func AnalyzeProject(ctx context.Context, group []Worktree, days int) Project {
	project := Project{Days: days, Worktrees: []Worktree{}, Branches: []Branch{}, Errors: []string{}}
	seen := make(map[string]bool)
	snapshots := make(map[string]string)
	var objects []string
	for _, item := range group {
		if seen[item.Repository] {
			continue
		}
		seen[item.Repository] = true
		items, err := list(ctx, item.Repository)
		if err != nil {
			project.Errors = append(project.Errors, item.Repository+": "+err.Error())
			continue
		}
		project.Worktrees = append(project.Worktrees, items...)
		for _, tree := range items {
			if tree.Error != "" {
				project.Errors = append(project.Errors, tree.Path+": "+tree.Error)
			}
		}
		shallow, err := gitContext(ctx, item.Repository, "rev-parse", "--is-shallow-repository")
		if err != nil {
			project.Errors = append(project.Errors, err.Error())
			continue
		}
		if strings.TrimSpace(shallow) == "true" {
			project.Errors = append(project.Errors, item.Repository+": shallow repository cannot prove full history retention")
			continue
		}
		output, err := gitContext(ctx, item.Repository, "rev-parse", "--path-format=absolute", "--git-path", "objects")
		if err != nil {
			project.Errors = append(project.Errors, err.Error())
			continue
		}
		objects = append(objects, strconv.Quote(strings.TrimSpace(output)))
		output, err = gitContext(ctx, item.Repository, "for-each-ref", "--format=%(refname) %(objectname) %(symref)", "refs/heads", "refs/remotes", "refs/stash")
		if err != nil {
			project.Errors = append(project.Errors, err.Error())
			continue
		}
		snapshots[item.Repository] = output
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			if fields[0] == "refs/stash" {
				for index := range project.Worktrees {
					if project.Worktrees[index].Repository == item.Repository {
						project.Worktrees[index].Stashed = true
					}
				}
				continue
			}
			branch := Branch{Repository: item.Repository, Name: fields[0], Head: fields[1], Commits: []Commit{}}
			for _, tree := range items {
				if tree.Branch == branch.Name && tree.Error == "" {
					branch.CheckedOut = true
					branch.PrimaryCheckout = branch.PrimaryCheckout || tree.Primary
				}
			}
			project.Branches = append(project.Branches, branch)
		}
		for _, tree := range items {
			if tree.Branch == "" && tree.Head != "" && !tree.Bare {
				project.Branches = append(project.Branches, Branch{Repository: item.Repository, Name: "detached: " + tree.Path, Head: tree.Head, CheckedOut: true})
			}
		}
	}
	project.MainRepository = canonicalRepository(project.Worktrees)
	if len(Groups(project.Worktrees)) > 1 {
		project.Errors = append(project.Errors, "repositories no longer share an origin or worktree registry")
		return project
	}
	if project.MainRepository == "" || len(project.Branches) == 0 {
		return project
	}
	dependencies, err := gitContext(ctx, project.MainRepository, "count-objects", "-v")
	if err != nil {
		project.Errors = append(project.Errors, err.Error())
		return project
	}
	if strings.Contains(dependencies, "alternate: ") {
		project.Errors = append(project.Errors, "main repository borrows Git objects; independent history retention cannot be proved")
		return project
	}
	run := func(args ...string) (string, error) {
		return gitObjects(ctx, project.MainRepository, strings.Join(objects, string(os.PathListSeparator)), args...)
	}
	heads := make(map[string]bool)
	args := []string{"log", "--topo-order", "--format=%H%x09%P%x09%ct%x09%s"}
	for _, branch := range project.Branches {
		if !heads[branch.Head] {
			heads[branch.Head] = true
			args = append(args, branch.Head)
		}
	}
	args = append(args, "--")
	output, err := run(args...)
	if err != nil {
		project.Errors = append(project.Errors, err.Error())
		return project
	}
	graph := make(map[string]historyNode)
	for _, line := range strings.Split(output, "\n") {
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) != 4 {
			continue
		}
		stamp, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			project.Errors = append(project.Errors, "invalid commit timestamp")
			return project
		}
		graph[fields[0]] = historyNode{strings.Fields(fields[1]), stamp, fields[3]}
	}
	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	contains, recent, err := branchHistory(ctx, graph, heads, cutoff)
	if err != nil {
		project.Errors = append(project.Errors, err.Error())
		return project
	}
	main := -1
	for index := range project.Branches {
		branch := &project.Branches[index]
		branch.LastCommit = graph[branch.Head].timestamp
		branch.Recent = len(recent[branch.Head])
		if strings.HasPrefix(branch.Name, "refs/heads/") {
			upstream := "refs/remotes/origin/" + strings.TrimPrefix(branch.Name, "refs/heads/")
			branch.LocalOnly = true
			for _, other := range project.Branches {
				if other.Repository == branch.Repository && other.Name == upstream && contains[other.Head][branch.Head] {
					branch.LocalOnly = false
				}
			}
		}
		if branch.Repository != project.MainRepository || !strings.HasPrefix(branch.Name, "refs/heads/") {
			continue
		}
		if main < 0 || betterBranch(*branch, project.Branches[main], contains) {
			main = index
		}
	}
	if main < 0 {
		main = 0
	}
	project.MainBranch = project.Branches[main].Name
	mainHead := project.Branches[main].Head
	mainHistory := make(map[string]bool)
	for _, commit := range recent[mainHead] {
		mainHistory[commit.Hash] = true
	}
	for index := range project.Branches {
		branch := &project.Branches[index]
		for _, commit := range recent[branch.Head] {
			if index == main || !mainHistory[commit.Hash] {
				branch.Commits = append(branch.Commits, commit)
			}
		}
		sort.Slice(branch.Commits, func(i, j int) bool {
			return graph[branch.Commits[i].Hash].timestamp > graph[branch.Commits[j].Hash].timestamp
		})
	}
	for index := range project.Worktrees {
		item := &project.Worktrees[index]
		item.Obsolete = false
		if item.Error != "" || item.Prunable || item.Bare {
			continue
		}
		item.Status = "outstanding"
		merged := item.Head != ""
		if item.Primary {
			merged = merged && item.Repository != project.MainRepository
			for _, other := range project.Worktrees {
				if other.Repository == item.Repository && !other.Primary {
					merged = false
				}
			}
			for _, branch := range project.Branches {
				if branch.Repository != item.Repository {
					continue
				}
				retained := false
				for _, other := range project.Branches {
					if other.Repository == project.MainRepository && strings.HasPrefix(other.Name, "refs/heads/") && contains[other.Head][branch.Head] {
						retained = true
					}
				}
				merged = merged && retained
			}
		} else {
			retained := false
			for _, branch := range project.Branches {
				if branch.Repository == item.Repository && branch.Name != item.Branch && strings.HasPrefix(branch.Name, "refs/heads/") && contains[branch.Head][item.Head] {
					retained = true
				}
			}
			merged = merged && retained
		}
		if merged {
			item.Status = "merged"
		}
		status, err := gitContext(ctx, item.Path, "status", "--porcelain=v2", "-z", "--no-renames", "--untracked-files=normal", "--ignored=matching")
		if err != nil {
			item.Error = err.Error()
			project.Errors = append(project.Errors, item.Path+": "+item.Error)
			continue
		}
		for _, field := range strings.Split(status, "\x00") {
			if strings.HasPrefix(field, "? ") || strings.HasPrefix(field, "! ") {
				item.LocalFiles = true
			}
			if strings.HasPrefix(field, "1 ") || strings.HasPrefix(field, "2 ") || strings.HasPrefix(field, "u ") {
				item.Dirty = true
			}
		}
		head, err := gitContext(ctx, item.Path, "rev-parse", "HEAD")
		if err != nil || strings.TrimSpace(head) != item.Head {
			item.Error = "HEAD changed during scan"
			project.Errors = append(project.Errors, item.Path+": "+item.Error)
		}
		item.Obsolete = merged && !item.Locked && !item.Dirty && !item.LocalFiles && !item.Stashed && item.Error == "" && len(project.Errors) == 0
	}
	for path, snapshot := range snapshots {
		output, err := gitContext(ctx, path, "for-each-ref", "--format=%(refname) %(objectname) %(symref)", "refs/heads", "refs/remotes", "refs/stash")
		if err != nil || output != snapshot {
			project.Errors = append(project.Errors, path+": branches changed or could not be rechecked during scan")
		}
	}
	if len(project.Errors) > 0 {
		for index := range project.Worktrees {
			project.Worktrees[index].Obsolete = false
		}
	}
	return project
}

func branchHistory(ctx context.Context, graph map[string]historyNode, heads map[string]bool, cutoff int64) (map[string]map[string]bool, map[string][]Commit, error) {
	contains := make(map[string]map[string]bool)
	recent := make(map[string][]Commit)
	for head := range heads {
		visited := make(map[string]bool)
		stack := []string{head}
		contains[head] = make(map[string]bool)
		for len(stack) > 0 {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			hash := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if visited[hash] {
				continue
			}
			visited[hash] = true
			node, found := graph[hash]
			if !found {
				return nil, nil, fmt.Errorf("incomplete history at %s", hash)
			}
			if heads[hash] {
				contains[head][hash] = true
			}
			if node.timestamp >= cutoff {
				recent[head] = append(recent[head], Commit{Hash: hash, Subject: node.subject, Date: time.Unix(node.timestamp, 0).UTC().Format("2006-01-02")})
			}
			stack = append(stack, node.parents...)
		}
	}
	return contains, recent, nil
}

func betterBranch(left, right Branch, contains map[string]map[string]bool) bool {
	if len(contains[left.Head]) != len(contains[right.Head]) {
		return len(contains[left.Head]) > len(contains[right.Head])
	}
	if left.PrimaryCheckout != right.PrimaryCheckout {
		return left.PrimaryCheckout
	}
	if left.Recent != right.Recent {
		return left.Recent > right.Recent
	}
	if left.CheckedOut != right.CheckedOut {
		return left.CheckedOut
	}
	if left.LocalOnly != right.LocalOnly {
		return left.LocalOnly
	}
	if left.LastCommit != right.LastCommit {
		return left.LastCommit > right.LastCommit
	}
	return left.Name < right.Name
}

func PrintProject(project Project, stdout io.Writer) {
	fmt.Fprintf(stdout, "[Repos] Branch work in the last %d days (read-only)\nMain repository: %s\nMain branch: %s\n", project.Days, ui.SanitizeTerminalString(project.MainRepository), ui.SanitizeTerminalString(project.MainBranch))
	for _, item := range project.Worktrees {
		label := "KEEP"
		if item.Obsolete {
			label = "CLEANUP CANDIDATE"
		}
		if item.Error != "" {
			label = "INVALID"
		}
		fmt.Fprintf(stdout, "%s | %s | %s | local changes: %t | local files: %t | stash: %t\n", label, ui.SanitizeTerminalString(item.Path), ui.SanitizeTerminalString(item.Branch), item.Dirty, item.LocalFiles, item.Stashed)
	}
	printed := make(map[string]bool)
	for _, branch := range project.Branches {
		if len(branch.Commits) == 0 && branch.Name != project.MainBranch {
			continue
		}
		fmt.Fprintf(stdout, "\nBranch: %s | %s | checked out: %t | ahead of/missing on origin: %t\n", ui.SanitizeTerminalString(branch.Name), ui.SanitizeTerminalString(branch.Repository), branch.CheckedOut, branch.LocalOnly)
		if printed[branch.Head] {
			fmt.Fprintln(stdout, "  Same tip; commits listed above.")
			continue
		}
		printed[branch.Head] = true
		for _, commit := range branch.Commits {
			fmt.Fprintf(stdout, "  %s %s %s\n", commit.Date, commit.Hash, ui.SanitizeTerminalString(commit.Subject))
		}
	}
	for _, err := range project.Errors {
		fmt.Fprintln(stdout, "Check incomplete: "+ui.SanitizeTerminalString(err))
	}
}
