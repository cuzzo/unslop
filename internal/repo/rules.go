package repo

import (
	"path/filepath"
	"strings"
)

// IsDebugBinary returns true if the given file path represents a debug binary or debug symbol structure.
func IsDebugBinary(path string) bool {
	cleanPath := filepath.ToSlash(path)
	lowerPath := strings.ToLower(cleanPath)

	if strings.Contains(lowerPath, ".dsym/") || strings.HasSuffix(lowerPath, ".dsym") {
		return true
	}

	ext := filepath.Ext(lowerPath)
	debugExts := map[string]bool{
		".pdb":  true,
		".elf":  true,
		".o":    true,
		".obj":  true,
		".gch":  true,
		".idb":  true,
		".ilk":  true,
		".map":  true,
		".suo":  true,
		".ncb":  true,
		".ipch": true,
		".d":    true,
	}

	if debugExts[ext] {
		return true
	}

	// Check filenames like debug.log, gmon.out, core
	base := filepath.Base(lowerPath)
	if base == "core" || strings.HasPrefix(base, "core.") || base == "gmon.out" {
		return true
	}

	return false
}

// IsLargeBinaryExtension returns true if the file extension is typically binary/compiled/media.
func IsLargeBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe":   true,
		".dll":   true,
		".so":    true,
		".dylib": true,
		".a":     true,
		".lib":   true,
		".bin":   true,
		".iso":   true,
		".tar":   true,
		".gz":    true,
		".zip":   true,
		".7z":    true,
		".pdf":   true,
		".mp4":   true,
		".png":   true,
		".jpg":   true,
		".jpeg":  true,
		".pyc":   true,
		".class": true,
		".jar":   true,
		".war":   true,
		".dmg":   true,
		".pkg":   true,
		".db":    true,
		".sqlite": true,
	}
	return binaryExts[ext]
}

// IsDependencyDumpPath returns true if the path belongs to a known language/framework package or build cache directory.
func IsDependencyDumpPath(path string) bool {
	cleanPath := filepath.ToSlash(path)
	parts := strings.Split(cleanPath, "/")

	depDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		"venv":         true,
		".venv":        true,
		"target":       true,
		"Pods":         true,
		"dist":         true,
		"build":        true,
		".gradle":      true,
		".nuget":       true,
		"__pycache__":  true,
		".next":        true,
		".nuxt":        true,
	}

	for _, part := range parts {
		if depDirs[part] {
			return true
		}
	}
	return false
}

// ExtractDependencyRoot returns the top-level dependency directory component if present.
func ExtractDependencyRoot(path string) string {
	cleanPath := filepath.ToSlash(path)
	parts := strings.Split(cleanPath, "/")

	depDirs := map[string]bool{
		"node_modules": true,
		"vendor":       true,
		"venv":         true,
		".venv":        true,
		"target":       true,
		"Pods":         true,
		"dist":         true,
		"build":        true,
		".gradle":      true,
		".nuget":       true,
		"__pycache__":  true,
		".next":        true,
		".nuxt":        true,
	}

	for i, part := range parts {
		if depDirs[part] {
			return strings.Join(parts[:i+1], "/") + "/"
		}
	}
	return ""
}

// IsGarbageDumpPath returns true for temporary, scratch, or dump files (.json data dumps, logs, etc.).
func IsGarbageDumpPath(path string) bool {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	ext := filepath.Ext(lowerPath)
	base := filepath.Base(lowerPath)

	if ext == ".json" {
		// Large/dump json patterns
		if strings.Contains(base, "dump") || strings.Contains(base, "trace") ||
			strings.Contains(base, "coverage") || strings.Contains(base, "scratch") ||
			strings.Contains(base, "log") || strings.Contains(base, "temp") ||
			strings.Contains(base, "tmp") || strings.Contains(base, "output") ||
			strings.Contains(base, "result") || strings.Contains(base, "data") {
			return true
		}
		return true // JSON files added & deleted are treated as candidate garbage
	}

	garbageExts := map[string]bool{
		".log":       true,
		".tmp":       true,
		".temp":      true,
		".bak":       true,
		".swp":       true,
		".ds_store":  true,
		".thumbs.db": true,
		".out":       true,
	}

	if garbageExts[ext] || base == ".ds_store" || base == "thumbs.db" {
		return true
	}

	return false
}

// ClassifyCandidate categorizes a file/path and determines its properties.
func ClassifyCandidate(path string, isDeleted bool, wasIgnoredAfterDelete bool, size int64) (category string, isDebug bool, riskClass string) {
	riskClass = "history-bloat"

	if IsDebugBinary(path) {
		return "Debug Binary", true, riskClass
	}

	if IsDependencyDumpPath(path) {
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

// IsSourceCodeFile returns true if the file extension or base name represents source code or project documentation.
func IsSourceCodeFile(path string) bool {
	cleanPath := filepath.ToSlash(path)
	if ExtractDependencyRoot(cleanPath) != "" {
		return false
	}

	ext := strings.ToLower(filepath.Ext(cleanPath))
	codeExts := map[string]bool{
		".go":      true,
		".rs":      true,
		".py":      true,
		".js":      true,
		".ts":      true,
		".jsx":     true,
		".tsx":     true,
		".c":       true,
		".cpp":     true,
		".cc":      true,
		".cxx":     true,
		".h":       true,
		".hpp":     true,
		".hh":      true,
		".java":    true,
		".kt":      true,
		".kts":     true,
		".rb":      true,
		".php":     true,
		".swift":   true,
		".m":       true,
		".mm":      true,
		".cs":      true,
		".sh":      true,
		".bash":    true,
		".zsh":     true,
		".fish":    true,
		".pl":      true,
		".pm":      true,
		".scala":   true,
		".clj":     true,
		".ex":      true,
		".exs":     true,
		".hs":      true,
		".lhs":     true,
		".erl":     true,
		".hrl":     true,
		".lua":     true,
		".r":       true,
		".rmd":     true,
		".v":       true,
		".sv":      true,
		".vhdl":    true,
		".zig":     true,
		".nim":     true,
		".f":       true,
		".f90":     true,
		".f95":     true,
		".pas":     true,
		".pp":      true,
		".sql":     true,
		".html":    true,
		".css":     true,
		".scss":    true,
		".less":    true,
		".vue":     true,
		".svelte":  true,
		".proto":   true,
		".graphql": true,
		".thrift":  true,
		".asm":     true,
		".s":       true,
		".cmake":   true,
		".toml":    true,
		".yaml":    true,
		".yml":     true,
		".xml":     true,
		".md":      true,
		".rst":     true,
	}

	if codeExts[ext] {
		return true
	}

	base := strings.ToLower(filepath.Base(cleanPath))
	codeBases := map[string]bool{
		"makefile":       true,
		"cmakelists.txt": true,
		"dockerfile":     true,
		"gemfile":        true,
		"rakefile":       true,
		"cargo.toml":     true,
		"package.json":   true,
		"go.mod":         true,
		"go.sum":         true,
		"license":        true,
		"readme":         true,
	}

	return codeBases[base]
}
