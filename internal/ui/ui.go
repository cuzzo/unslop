package ui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/yahn/unslop/internal/config"
	"github.com/yahn/unslop/internal/format"
	"github.com/yahn/unslop/internal/scanner"
)

func FormatBytes(b int64) string {
	return format.FormatBytes(b)
}

func FormatUintBytes(b uint64) string {
	return format.FormatUintBytes(b)
}

func FormatNumber(n int64) string {
	return format.FormatNumber(n)
}

func RenderProgressBar(percentage float64, width int) string {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	filledLen := int((percentage / 100.0) * float64(width))
	if filledLen > width {
		filledLen = width
	}

	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < filledLen; i++ {
		sb.WriteString("█")
	}
	for i := filledLen; i < width; i++ {
		sb.WriteString("░")
	}
	sb.WriteString("]")
	return sb.String()
}

func SanitizeTerminalString(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func FindFzf() string {
	path, err := exec.LookPath("fzf")
	if err == nil {
		return path
	}
	return ""
}

func RunFzfInteractive(candidates []scanner.Candidate, fzfBin string, diskTotal, diskUsed, diskFree uint64) []scanner.Candidate {
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "No stale candidates found matching criteria.\n")
		return nil
	}

	var totalSizeBytes int64
	for _, c := range candidates {
		totalSizeBytes += c.Size
	}

	candMap := make(map[string]scanner.Candidate, len(candidates))
	var inputBuf bytes.Buffer

	for _, c := range candidates {
		token := fmt.Sprintf("cand-%d", c.ID)
		candMap[token] = c

		sanitizedPath := SanitizeTerminalString(c.Path)
		abbrevPath := format.AbbreviateHomePath(sanitizedPath)
		sanitizedCategory := SanitizeTerminalString(c.Category)

		idTag := fmt.Sprintf("[%d]", c.ID)
		paddedID := fmt.Sprintf("%-5s", idTag)
		isNonDeletable := !c.CanDelete || c.ProposedAction == "report-only"

		var tags []string
		if isNonDeletable {
			tags = append(tags, "[CANNOT DELETE]")
		}
		if c.IsGitIgnored {
			tags = append(tags, "[GITIGNORE]")
		}

		pathWithTags := abbrevPath
		if len(tags) > 0 {
			pathWithTags = strings.Join(tags, " ") + " " + abbrevPath
		}

		displayLine := fmt.Sprintf("%s %10s | %s | %-16s | %s", paddedID, FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), sanitizedCategory, pathWithTags)

		inputBuf.WriteString(token)
		inputBuf.WriteByte('\t')
		inputBuf.WriteString(displayLine)
		inputBuf.WriteByte(0)
	}

	headerStr := fmt.Sprintf(
		"unslop v%s | Total: %s | Used: %s | Free: %s | Candidates: %d (%s)\nControls: TAB: Select & Next | Shift-TAB: Select & Prev | Backspace/Del: Unselect & Prev | Ctrl-A: Select All | Enter: Confirm Selection",
		config.Version, FormatUintBytes(diskTotal), FormatUintBytes(diskUsed), FormatUintBytes(diskFree),
		len(candidates), FormatBytes(totalSizeBytes),
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
		"--prompt=Select items to clean> ",
		"--bind=tab:toggle+down,btab:toggle+up,bspace:deselect+up,bs:deselect+up,delete:deselect+up,del:deselect+up,ctrl-a:select-all",
		"--pointer=❯ ",
		"--marker=x ",
		"--color=fg:white,hl:yellow,pointer:cyan,marker:red",
	)

	cmd.Stdin = &inputBuf
	cmd.Stderr = os.Stderr

	outBytes, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 130 || exitErr.ExitCode() == 1 {
				fmt.Fprintln(os.Stderr, "Selection cancelled.")
				return nil
			}
		}
		fmt.Fprintf(os.Stderr, "Error executing fzf: %v\n", err)
		return nil
	}

	if len(outBytes) == 0 {
		return nil
	}

	lines := bytes.Split(outBytes, []byte{0})
	var selected []scanner.Candidate

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
			if cand.CanDelete && cand.ProposedAction != "report-only" {
				selected = append(selected, cand)
			}
		}
	}

	return selected
}
