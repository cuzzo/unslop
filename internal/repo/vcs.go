package repo

import "io"

type VCSKind string

const (
	VCSGit VCSKind = "git"
)

type HistoryCandidate struct {
	ID          int    `json:"id"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Category    string `json:"category"`
	RiskClass   string `json:"risk_class"`
	Status      string `json:"status"` // "deleted" or "existing"
	IsDebug     bool   `json:"is_debug"`
	CommitCount int    `json:"commit_count"`
	CanDelete   bool   `json:"can_delete"`
}

type ScanOptions struct {
	MinSizeMB      float64
	NonInteractive bool
	OutputFile     string
	Stderr         io.Writer
}

type VCSAnalyzer interface {
	Kind() VCSKind
	Detect(repoPath string) bool
	AnalyzeHistory(repoPath string, opts ScanOptions) ([]HistoryCandidate, error)
}
