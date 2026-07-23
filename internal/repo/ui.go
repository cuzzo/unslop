package repo

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/yahn/unslop/internal/format"
	"github.com/yahn/unslop/internal/ui"
)

// RunRepoUI presents history candidates to the user via fzf TUI or text output.
func RunRepoUI(candidates []HistoryCandidate, fzfBin string, nonInteractive bool, stdout, stderr io.Writer) []HistoryCandidate {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	if len(candidates) == 0 {
		fmt.Fprintln(stdout, "[UNSLOP REPO] No repository history bloat candidates found matching scan criteria.")
		return nil
	}

	var totalSizeBytes int64
	for _, c := range candidates {
		totalSizeBytes += c.Size
	}

	if nonInteractive || fzfBin == "" {
		if fzfBin == "" && !nonInteractive {
			fmt.Fprintln(stderr, "\n[PLAN REPORT] fzf runtime binary not found. Standard repository history bloat summary output below:")
		}

		fmt.Fprintf(stdout, "Candidate items found in Git history (%d total, %s):\n", len(candidates), format.FormatBytes(totalSizeBytes))
		for _, c := range candidates {
			idTag := fmt.Sprintf("[%d]", c.ID)
			paddedID := fmt.Sprintf("%-5s", idTag)

			var tags []string
			if c.IsDebug {
				tags = append(tags, "[DEBUG BINARY]")
			}
			if c.Status == "deleted" {
				tags = append(tags, "[DELETED]")
			} else {
				tags = append(tags, "[EXISTING]")
			}

			tagStr := strings.Join(tags, " ")
			fmt.Fprintf(stdout, " %s [%-16s | %-20s] %10s | %s %s\n",
				paddedID, c.RiskClass, c.Category, format.FormatBytes(c.Size), tagStr, c.Path)
		}
		// In non-interactive or non-fzf mode, select all candidates for manifest generation
		return candidates
	}

	candMap := make(map[string]HistoryCandidate, len(candidates))
	var inputBuf bytes.Buffer

	for _, c := range candidates {
		token := fmt.Sprintf("cand-%d", c.ID)
		candMap[token] = c

		sanitizedPath := ui.SanitizeTerminalString(c.Path)
		sanitizedCategory := ui.SanitizeTerminalString(c.Category)

		idTag := fmt.Sprintf("[%d]", c.ID)
		paddedID := fmt.Sprintf("%-5s", idTag)

		var tags []string
		if c.IsDebug {
			tags = append(tags, "[DEBUG BINARY]")
		}
		if c.Status == "deleted" {
			tags = append(tags, "[DELETED]")
		} else {
			tags = append(tags, "[EXISTING]")
		}

		pathWithTags := sanitizedPath
		if len(tags) > 0 {
			pathWithTags = strings.Join(tags, " ") + " " + sanitizedPath
		}

		displayLine := fmt.Sprintf("%s %10s | %-16s | %s", paddedID, format.FormatBytes(c.Size), sanitizedCategory, pathWithTags)

		inputBuf.WriteString(token)
		inputBuf.WriteByte('\t')
		inputBuf.WriteString(displayLine)
		inputBuf.WriteByte(0)
	}

	headerStr := fmt.Sprintf(
		"unslop repo | Candidates: %d (%s reclaimable)\nControls: TAB: Select & Next | Shift-TAB: Select & Prev | Ctrl-A: Select All | Enter: Confirm Selection & Write git-filter-repo Manifest",
		len(candidates), format.FormatBytes(totalSizeBytes),
	)

	cmd := exec.Command(fzfBin,
		"--ansi",
		"--layout=reverse",
		"--multi",
		"--read0",
		"--print0",
		"--delimiter=\t",
		"--with-nth=2..",
		"--header="+headerStr,
		"--prompt=Select git-filter-repo candidates> ",
		"--bind=tab:toggle+down,btab:toggle+up,bspace:deselect+up,bs:deselect+up,delete:deselect+up,del:deselect+up,ctrl-a:select-all",
		"--pointer=❯ ",
		"--marker=x ",
		"--color=fg:white,hl:yellow,pointer:cyan,marker:red",
	)

	cmd.Stdin = &inputBuf
	cmd.Stderr = stderr

	outBytes, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 130 || exitErr.ExitCode() == 1 {
				fmt.Fprintln(stderr, "Selection cancelled.")
				return nil
			}
		}
		fmt.Fprintf(stderr, "Error executing fzf: %v\n", err)
		return nil
	}

	if len(outBytes) == 0 {
		return nil
	}

	lines := bytes.Split(outBytes, []byte{0})
	var selected []HistoryCandidate

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		strLine := string(line)
		idx := strings.IndexByte(strLine, '\t')
		token := strLine
		if idx != -1 {
			token = strLine[:idx]
		}
		token = strings.TrimSpace(token)
		if cand, ok := candMap[token]; ok {
			selected = append(selected, cand)
		}
	}

	return selected
}
