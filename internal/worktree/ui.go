package worktree

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/yahn/unslop/internal/ui"
)

func Groups(items []Worktree) [][]Worktree {
	parents := make(map[string]string)
	find := func(key string) string {
		start := key
		for range len(parents) {
			parent, found := parents[key]
			if !found {
				break
			}
			key = parent
		}
		if start != key {
			parents[start] = key
		}
		return key
	}
	for _, item := range items {
		for _, remote := range item.Remotes {
			left, right := find("repo:"+item.Repository), find("remote:"+remote)
			if left != right {
				parents[left] = right
			}
		}
	}
	var groups [][]Worktree
	indices := make(map[string]int)
	for _, item := range items {
		key := find("repo:" + item.Repository)
		index, found := indices[key]
		if !found {
			index = len(groups)
			indices[key] = index
			groups = append(groups, nil)
		}
		groups[index] = append(groups[index], item)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0].Repository < groups[j][0].Repository })
	return groups
}

func projectLabel(group []Worktree) string {
	if len(group[0].Remotes) > 0 {
		return strings.Join(group[0].Remotes, ", ")
	}
	return group[0].Repository
}

func repositoryRows(items []Worktree) (bytes.Buffer, map[string][]Worktree) {
	var validItems []Worktree
	for _, item := range items {
		if item.Error == "" && !item.Prunable {
			validItems = append(validItems, item)
		}
	}
	var input bytes.Buffer
	tokens := make(map[string][]Worktree)
	identifiers := make(map[string]string)
	for _, item := range items {
		if _, found := identifiers[item.Repository]; !found {
			identifiers[item.Repository] = strconv.Itoa(len(identifiers))
		}
	}
	for _, group := range Groups(validItems) {
		if len(group) < 2 {
			continue
		}
		token := identifiers[group[0].Repository]
		for _, item := range group {
			tokens[identifiers[item.Repository]] = group
		}
		review, obsolete := 0, 0
		for _, item := range group {
			if item.Status != "merged" || item.Error != "" || item.Dirty || item.LocalFiles {
				review++
			}
			if item.Obsolete {
				obsolete++
			}
		}
		summary := fmt.Sprintf("%3d checkouts | review: %d | obsolete: %d", len(group), review, obsolete)
		if group[0].Status == "unchecked" {
			summary = fmt.Sprintf("%3d checkouts | Enter: analyse history", len(group))
		}
		fmt.Fprintf(&input, "%s\t%s | %s | %s\x00", token, summary, ui.SanitizeTerminalString(projectLabel(group)), ui.SanitizeTerminalString(canonicalRepository(group)))
	}
	return input, tokens
}

func selectorCommand(fzfBin string, stderr io.Writer) *exec.Cmd {
	cmd := exec.Command(fzfBin, "--read0", "--print0", "--delimiter=\t", "--with-nth=2..", "--layout=reverse", "--expect=ctrl-f",
		"--bind=f:print(f)+accept,/:unbind(f)+change-prompt(Search repos> )",
		"--header=Files (f) | [Repos] (r)\nRead-only: Enter analyses selected repositories. /: Search | Esc: Quit", "--prompt=Repos> ")
	cmd.Stderr = stderr
	return cmd
}

func selectedOutput(output []byte, err error, tokens map[string][]Worktree) ([]Worktree, bool, error) {
	fields := ui.SelectionTokens(output)
	if fields[0] == "f" || fields[0] == "ctrl-f" {
		return nil, true, nil
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && (exit.ExitCode() == 1 || exit.ExitCode() == 130) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var selected []Worktree
	for _, token := range fields {
		if group, found := tokens[token]; found {
			selected = append(selected, group...)
		}
	}
	return selected, false, nil
}
