package worktree

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type Commit struct {
	Hash    string `json:"hash"`
	Subject string `json:"subject"`
	Date    string `json:"date,omitempty"`
}

type Worktree struct {
	Repository     string   `json:"repository"`
	Remotes        []string `json:"remotes,omitempty"`
	Path           string   `json:"path"`
	Branch         string   `json:"branch"`
	Head           string   `json:"head"`
	Primary        bool     `json:"primary"`
	Bare           bool     `json:"bare"`
	Locked         bool     `json:"locked"`
	Prunable       bool     `json:"prunable"`
	PrunableReason string   `json:"prunable_reason,omitempty"`
	Dirty          bool     `json:"dirty"`
	LocalFiles     bool     `json:"local_files"`
	Stashed        bool     `json:"stashed_work"`
	Status         string   `json:"status"`
	Obsolete       bool     `json:"obsolete"`
	Error          string   `json:"error,omitempty"`
}

func remoteKey(repository, address string) string {
	if strings.HasPrefix(address, "ext::") {
		return fmt.Sprintf("custom:%x", sha256.Sum256([]byte(address)))
	}
	if !strings.Contains(address, "://") {
		colon := strings.IndexByte(address, ':')
		if bracket := strings.Index(address, "]:"); bracket >= 0 {
			colon = bracket + 1
		}
		if colon >= 0 && !filepath.IsAbs(address) {
			host, path := address[:colon], address[colon+1:]
			host = host[strings.LastIndex(host, "@")+1:]
			return strings.ToLower(host) + "/" + strings.TrimSuffix(strings.Trim(path, "/"), ".git")
		}
		if !filepath.IsAbs(address) {
			address = filepath.Join(repository, address)
		}
		if actual, err := filepath.EvalSymlinks(address); err == nil {
			address = actual
		}
		return "file:" + filepath.Clean(address)
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return fmt.Sprintf("custom:%x", sha256.Sum256([]byte(address)))
	}
	if parsed.Scheme == "file" {
		if parsed.Host == "" || parsed.Host == "localhost" {
			return remoteKey(repository, parsed.Path)
		}
		return "file://" + strings.ToLower(parsed.Host) + parsed.EscapedPath()
	}
	key := strings.ToLower(parsed.Host) + "/" + strings.TrimSuffix(strings.Trim(parsed.EscapedPath(), "/"), ".git")
	if parsed.RawQuery != "" {
		key += fmt.Sprintf("?sha256=%x", sha256.Sum256([]byte(parsed.RawQuery)))
	}
	return key
}

func gitContext(ctx context.Context, path string, args ...string) (string, error) {
	return gitObjects(ctx, path, "", args...)
}

func gitObjects(ctx context.Context, path, objects string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"--no-optional-locks", "-C", path, "-c", "core.fsmonitor=false"}, args...)...)
	for _, variable := range os.Environ() {
		name, _, _ := strings.Cut(variable, "=")
		switch name {
		case "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE":
		default:
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_NO_LAZY_FETCH=1")
	if objects != "" {
		cmd.Env = append(cmd.Env, "GIT_ALTERNATE_OBJECT_DIRECTORIES="+objects)
	}
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("git %s: %w: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", err
	}
	return string(out), nil
}

func parseWorktrees(output string) []Worktree {
	var result []Worktree
	for _, record := range strings.Split(output, "\x00\x00") {
		var item Worktree
		for _, field := range strings.Split(record, "\x00") {
			key, value, _ := strings.Cut(field, " ")
			switch key {
			case "worktree":
				item.Path = value
			case "HEAD":
				if strings.Trim(value, "0") != "" {
					item.Head = value
				}
			case "branch":
				item.Branch = value
			case "bare":
				item.Bare = true
			case "locked":
				item.Locked = true
			case "prunable":
				item.Prunable = true
				item.PrunableReason = value
			}
		}
		if item.Path != "" {
			item.Primary = len(result) == 0
			result = append(result, item)
		}
	}
	return result
}

func List(path string) ([]Worktree, error) {
	return list(context.Background(), path)
}

func list(ctx context.Context, path string) ([]Worktree, error) {
	common, err := gitContext(ctx, path, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return nil, err
	}
	common, err = filepath.EvalSymlinks(strings.TrimSuffix(common, "\n"))
	if err != nil {
		return nil, err
	}
	output, err := gitContext(ctx, path, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return nil, err
	}
	items := parseWorktrees(output)
	if len(items) == 0 {
		return nil, fmt.Errorf("git returned no worktrees for %q", path)
	}
	output, err = gitContext(ctx, path, "remote", "-v")
	if err != nil {
		return nil, err
	}
	var remotes []string
	for _, line := range strings.Split(output, "\n") {
		name, address, found := strings.Cut(line, "\t")
		if found && name == "origin" && strings.HasSuffix(address, " (fetch)") {
			key := remoteKey(items[0].Path, strings.TrimSuffix(address, " (fetch)"))
			if !slices.Contains(remotes, key) {
				remotes = append(remotes, key)
			}
		}
	}
	for index := range items {
		items[index].Repository = items[0].Path
		items[index].Remotes = remotes
		items[index].Status = "unchecked"
		item := &items[index]
		if item.Prunable {
			item.Error = "missing or stale worktree registration"
			continue
		}
		if !item.Bare {
			if _, err := os.Lstat(filepath.Join(item.Path, ".git")); err != nil {
				item.Error = err.Error()
				continue
			}
			root, err := gitContext(ctx, item.Path, "rev-parse", "--show-toplevel")
			actual, resolveErr := filepath.EvalSymlinks(strings.TrimSpace(root))
			if err != nil || resolveErr != nil || actual != item.Path {
				item.Error = "checkout is not a valid repository root"
				continue
			}
			owner, err := gitContext(ctx, item.Path, "rev-parse", "--path-format=absolute", "--git-common-dir")
			owner, resolveErr = filepath.EvalSymlinks(strings.TrimSuffix(owner, "\n"))
			if err != nil || resolveErr != nil || owner != common {
				item.Error = "checkout does not belong to this worktree registry"
			}
		}
	}
	return items, nil
}
