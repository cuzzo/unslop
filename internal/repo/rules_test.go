package repo

import (
	"testing"
)

func TestRulesClassification(t *testing.T) {
	tests := []struct {
		path            string
		expectedDebug   bool
		expectedDep     bool
		expectedGarbage bool
		expectedBin     bool
	}{
		{"bin/debug.pdb", true, false, false, false},
		{"build/app.elf", true, true, false, false},
		{"src/main.o", true, false, false, false},
		{"App.dSYM/Contents/Resources/DWARF/App", true, false, false, false},
		{"node_modules/express/index.js", false, true, false, false},
		{"vendor/github.com/pkg/errors/errors.go", false, true, false, false},
		{"venv/lib/python3.9/site-packages/pkg.py", false, true, false, false},
		{"target/debug/repowise", false, true, false, false},
		{"data/trace_dump.json", false, false, true, false},
		{"logs/app.log", false, false, true, false},
		{"tmp/scratch.tmp", false, false, true, false},
		{"build/release.exe", false, true, false, true},
		{"archive/backup.zip", false, false, false, true},
		{"assets/image.png", false, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsDebugBinary(tt.path); got != tt.expectedDebug {
				t.Errorf("IsDebugBinary(%q) = %v; want %v", tt.path, got, tt.expectedDebug)
			}
			if got := IsDependencyDumpPath(tt.path); got != tt.expectedDep {
				t.Errorf("IsDependencyDumpPath(%q) = %v; want %v", tt.path, got, tt.expectedDep)
			}
			if got := IsGarbageDumpPath(tt.path); got != tt.expectedGarbage {
				t.Errorf("IsGarbageDumpPath(%q) = %v; want %v", tt.path, got, tt.expectedGarbage)
			}
			if got := IsLargeBinaryExtension(tt.path); got != tt.expectedBin {
				t.Errorf("IsLargeBinaryExtension(%q) = %v; want %v", tt.path, got, tt.expectedBin)
			}
		})
	}
}

func TestExtractDependencyRoot(t *testing.T) {
	if got := ExtractDependencyRoot("foo/node_modules/bar/baz.js"); got != "foo/node_modules/" {
		t.Errorf("ExtractDependencyRoot() = %q; want %q", got, "foo/node_modules/")
	}
	if got := ExtractDependencyRoot("src/main.go"); got != "" {
		t.Errorf("ExtractDependencyRoot() = %q; want empty", got)
	}
}

func TestClassifyCandidate(t *testing.T) {
	cat, debug, risk := ClassifyCandidate("debug.pdb", true, false, 100)
	if cat != "Debug Binary" || !debug || risk != "history-bloat" {
		t.Errorf("ClassifyCandidate(debug.pdb) = (%q, %v, %q)", cat, debug, risk)
	}

	cat, debug, _ = ClassifyCandidate("node_modules/pkg.js", false, false, 100)
	if cat != "Dependency Dump" || debug {
		t.Errorf("ClassifyCandidate(node_modules) = (%q, %v)", cat, debug)
	}

	cat, _, _ = ClassifyCandidate("deleted.txt", true, true, 100)
	if cat != "Deleted Then Ignored" {
		t.Errorf("ClassifyCandidate(deleted.txt) = %q; want 'Deleted Then Ignored'", cat)
	}

	cat, _, _ = ClassifyCandidate("data_dump.json", true, false, 100)
	if cat != "Garbage JSON Dump" {
		t.Errorf("ClassifyCandidate(data_dump.json) = %q", cat)
	}

	cat, _, _ = ClassifyCandidate("scratch.tmp", true, false, 100)
	if cat != "Garbage File" {
		t.Errorf("ClassifyCandidate(scratch.tmp) = %q", cat)
	}

	cat, _, _ = ClassifyCandidate("archive.zip", false, false, 100)
	if cat != "Large Binary" {
		t.Errorf("ClassifyCandidate(archive.zip) = %q", cat)
	}

	cat, _, _ = ClassifyCandidate("old.unknown", true, false, 100)
	if cat != "Deleted File Bloat" {
		t.Errorf("ClassifyCandidate(old.unknown) = %q; want 'Deleted File Bloat'", cat)
	}
}

func TestIsSourceCodeFile(t *testing.T) {
	codeFiles := []string{
		"main.go", "lib.rs", "app.py", "index.js", "types.ts",
		"server.cpp", "header.h", "Class.java", "script.sh",
		"Makefile", "CMakeLists.txt", "Cargo.toml", "README.md",
	}

	for _, f := range codeFiles {
		if !IsSourceCodeFile(f) {
			t.Errorf("IsSourceCodeFile(%q) = false; want true", f)
		}
	}

	nonCodeFiles := []string{
		"app.pdb", "data.json", "archive.zip", "temp.tmp", "node_modules/index.js",
	}

	for _, f := range nonCodeFiles {
		if IsSourceCodeFile(f) {
			t.Errorf("IsSourceCodeFile(%q) = true; want false", f)
		}
	}
}
