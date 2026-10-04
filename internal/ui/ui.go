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

func CandidatePath(c scanner.Candidate, cannotDelete bool) string {
	var tags []string
	if cannotDelete {
		tags = append(tags, "[CANNOT DELETE]")
	}
	if c.IsGitIgnored {
		tags = append(tags, "[GITIGNORE]")
	}
	if c.IsDevBinary {
		tags = append(tags, "[DEV BINARY]")
	}
	path := format.AbbreviateHomePath(c.Path)
	if len(tags) > 0 {
		path = strings.Join(tags, " ") + " " + path
	}
	return path
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

func fileRows(candidates []scanner.Candidate) (bytes.Buffer, map[string]scanner.Candidate) {
	candMap := make(map[string]scanner.Candidate, len(candidates))
	var inputBuf bytes.Buffer

	for index, c := range candidates {
		token := fmt.Sprintf("cand-%d", index+1)
		candMap[token] = c

		c.Path = SanitizeTerminalString(c.Path)
		sanitizedCategory := SanitizeTerminalString(c.Category)

		idTag := fmt.Sprintf("[%d]", index+1)
		paddedID := fmt.Sprintf("%-5s", idTag)
		isNonDeletable := !c.CanDelete

		fmt.Fprintf(&inputBuf, "%s\t%s %10s | %s | %-16s | %s\x00", token, paddedID, format.FormatBytes(c.Size), format.FormatAgeDays(c.AgeDays), sanitizedCategory, CandidatePath(c, isNonDeletable))
	}

	return inputBuf, candMap
}

func fileSelector(fzfBin string, diskTotal, diskUsed, diskFree uint64) *exec.Cmd {

	headerStr := fmt.Sprintf(
		"[Files] (f) | Repos (r)\nunslop v%s | Total: %s | Used: %s | Free: %s\nControls: /: Search | TAB: Select & Next | Shift-TAB: Select & Prev | Backspace/Del: Unselect & Prev | Ctrl-A: Select All | Enter: Confirm Selection",
		config.Version, format.FormatUintBytes(diskTotal), format.FormatUintBytes(diskUsed), format.FormatUintBytes(diskFree),
	)

	cmd := exec.Command(fzfBin,
		"--ansi",
		"--layout=reverse",
		"--multi",
		"--read0",
		"--print0",
		"--expect=ctrl-w",
		"--delimiter=\t",
		"--with-nth=2..",
		"--header="+headerStr,
		"--prompt=Select items to clean> ",
		"--bind=r:print(r)+accept,/:unbind(r)+change-prompt(Search files> ),tab:toggle+down,btab:toggle+up,bspace:deselect+up,bs:deselect+up,delete:deselect+up,del:deselect+up,ctrl-a:select-all",
		"--pointer=❯ ",
		"--marker=x ",
		"--color=fg:white,hl:yellow,pointer:cyan,marker:red",
	)

	cmd.Stderr = os.Stderr
	return cmd
}

func selectedFiles(outBytes []byte, err error, candMap map[string]scanner.Candidate) ([]scanner.Candidate, bool, error) {
	tokens := SelectionTokens(outBytes)
	if tokens[0] == "r" || tokens[0] == "ctrl-w" {
		return nil, true, nil
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 130 || exitErr.ExitCode() == 1 {
				fmt.Fprintln(os.Stderr, "Selection cancelled.")
				return nil, false, nil
			}
		}
		return nil, false, err
	}

	if len(outBytes) == 0 {
		return nil, false, nil
	}

	var selected []scanner.Candidate

	for _, token := range tokens {
		if cand, ok := candMap[token]; ok {
			if cand.CanDelete {
				selected = append(selected, cand)
			}
		}
	}

	return selected, false, nil
}

func SelectionTokens(output []byte) []string {
	fields := bytes.Split(bytes.TrimPrefix(output, []byte{0}), []byte{0})
	tokens := make([]string, len(fields))
	for index, field := range fields {
		token, _, _ := strings.Cut(string(field), "\t")
		tokens[index] = strings.TrimSpace(token)
	}
	return tokens
}
