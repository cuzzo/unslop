package repo

import (
	"path/filepath"
	"strings"
)

func IsDebugBinary(path string) bool {
	cleanPath := filepath.ToSlash(path)
	lowerPath := strings.ToLower(cleanPath)

	if strings.Contains(lowerPath, ".dsym/") || strings.HasSuffix(lowerPath, ".dsym") {
		return true
	}

	ext := filepath.Ext(lowerPath)
	switch ext {
	case ".pdb", ".elf", ".o", ".obj", ".gch", ".idb", ".ilk", ".map", ".suo", ".ncb", ".ipch", ".d":
		return true
	}

	base := filepath.Base(lowerPath)
	if base == "core" || strings.HasPrefix(base, "core.") || base == "gmon.out" {
		return true
	}

	return false
}

func IsLargeBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".bin", ".iso", ".tar", ".gz":
		return true
	case ".zip", ".7z", ".pdf", ".mp4", ".png", ".jpg", ".jpeg", ".pyc", ".class", ".jar":
		return true
	case ".war", ".dmg", ".pkg", ".db", ".sqlite":
		return true
	}

	return false
}

func ExtractDependencyRoot(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, part := range parts {
		if isDependencyDir(part) {
			return strings.Join(parts[:i+1], "/") + "/"
		}
	}
	return ""
}

func isDependencyDir(name string) bool {
	switch name {
	case "node_modules", "vendor", "venv", ".venv", "target", "Pods", "dist", "build", ".gradle", ".nuget", "__pycache__", ".next", ".nuxt":
		return true
	}
	return false
}

func IsGarbageDumpPath(path string) bool {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	ext := filepath.Ext(lowerPath)
	base := filepath.Base(lowerPath)

	switch ext {
	case ".json", ".log", ".tmp", ".temp", ".bak", ".swp", ".ds_store", ".thumbs.db", ".out":
		return true
	}

	if base == ".ds_store" || base == "thumbs.db" {
		return true
	}

	return false
}

func ClassifyCandidate(path string, isDeleted bool, wasIgnoredAfterDelete bool) (category string, isDebug bool, riskClass string) {
	riskClass = "history-bloat"

	if IsDebugBinary(path) {
		return "Debug Binary", true, riskClass
	}

	if ExtractDependencyRoot(path) != "" {
		return "Dependency Dump", false, riskClass
	}

	if wasIgnoredAfterDelete {
		return "Deleted Then Ignored", false, riskClass
	}

	if IsGarbageDumpPath(path) {
		if strings.HasSuffix(strings.ToLower(path), ".json") {
			return "Garbage JSON Dump", false, riskClass
		}
		return "Garbage File", false, riskClass
	}

	if IsLargeBinaryExtension(path) {
		return "Large Binary", false, riskClass
	}

	if isDeleted {
		return "Deleted File Bloat", false, riskClass
	}

	return "Large Historical File", false, riskClass
}

func IsSourceCodeFile(path string) bool {
	cleanPath := filepath.ToSlash(path)
	if ExtractDependencyRoot(cleanPath) != "" {
		return false
	}

	ext := strings.ToLower(filepath.Ext(cleanPath))
	switch ext {
	case ".go", ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".cc":
		return true
	case ".cxx", ".h", ".hpp", ".hh", ".java", ".kt", ".kts", ".rb", ".php", ".swift":
		return true
	case ".m", ".mm", ".cs", ".sh", ".bash", ".zsh", ".fish", ".pl", ".pm", ".scala":
		return true
	case ".clj", ".ex", ".exs", ".hs", ".lhs", ".erl", ".hrl", ".lua", ".r", ".rmd":
		return true
	case ".v", ".sv", ".vhdl", ".zig", ".nim", ".f", ".f90", ".f95", ".pas", ".pp":
		return true
	case ".sql", ".html", ".css", ".scss", ".less", ".vue", ".svelte", ".proto", ".graphql", ".thrift":
		return true
	case ".asm", ".s", ".cmake", ".toml", ".yaml", ".yml", ".xml", ".md", ".rst":
		return true
	}

	base := strings.ToLower(filepath.Base(cleanPath))
	switch base {
	case "makefile", "cmakelists.txt", "dockerfile", "gemfile", "rakefile", "cargo.toml", "package.json", "go.mod", "go.sum", "license", "readme":
		return true
	}

	return false
}
