package repo

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/yahn/unslop/internal/format"
)

// WriteFilterManifest writes selected history candidates to a manifest file for git-filter-repo.
func WriteFilterManifest(candidates []HistoryCandidate, outputPath string) error {
	if outputPath == "" {
		outputPath = "unslop-git-filter.txt"
	}

	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory for filter manifest: %w", err)
		}
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create filter manifest file '%s': %w", outputPath, err)
	}
	defer f.Close()

	for _, c := range candidates {
		_, err := fmt.Fprintln(f, c.Path)
		if err != nil {
			return fmt.Errorf("failed to write path to filter manifest: %w", err)
		}
	}

	return nil
}

// FormatInstructions generates human-readable post-processing instructions for git-filter-repo.
func FormatInstructions(manifestPath string, selectedCount int, totalBytes int64) string {
	if manifestPath == "" {
		manifestPath = "unslop-git-filter.txt"
	}

	relPath := format.AbbreviateHomePath(manifestPath)
	sizeStr := format.FormatBytes(totalBytes)

	return fmt.Sprintf(
		"\n[UNSLOP REPO] Successfully generated Git history filter file: %s\n"+
			"Selected candidates: %d (%s reclaimable)\n\n"+
			"To purge these selected candidates from Git history using git-filter-repo, run:\n"+
			"    git-filter-repo --invert-paths --paths-from-file %s\n\n"+
			"Note: git-filter-repo is the State-of-the-Art Git history rewriting tool.\n"+
			"Ensure you have created a mirror clone or full backup of your repository before rewriting history.\n",
		relPath, selectedCount, sizeStr, relPath,
	)
}
