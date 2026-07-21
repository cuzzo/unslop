package format

import (
	"fmt"
	"os"
	"strings"
)

func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func FormatUintBytes(b uint64) string {
	return FormatBytes(int64(b))
}

func FormatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(in)+(len(in)-1)/3)
	for i, c := range []byte(in) {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

func AbbreviateHomePath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	if strings.HasPrefix(path, home+"/") {
		return "~/" + path[len(home)+1:]
	}
	if strings.HasPrefix(path, home+"\\") {
		return "~\\" + path[len(home)+1:]
	}
	return path
}

func FormatAgeDays(ageDays float64) string {
	if ageDays >= 100.0 {
		return fmt.Sprintf("%5.0fd", ageDays)
	}
	return fmt.Sprintf("%5.1fd", ageDays)
}
