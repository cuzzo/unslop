package repo

import "io"

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
	MinSizeMB float64
	Stderr    io.Writer
}
