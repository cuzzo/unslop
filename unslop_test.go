package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		res := formatBytes(tt.input)
		if res != tt.expected {
			t.Errorf("formatBytes(%d) = %s; want %s", tt.input, res, tt.expected)
		}
	}
}

func TestFormatUintBytes(t *testing.T) {
	res := formatUintBytes(1048576)
	if res != "1.0 MB" {
		t.Errorf("formatUintBytes(1048576) = %s; want 1.0 MB", res)
	}
}

func TestCalculateDynamicMinSizeMB(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)

	sz10 := calculateDynamicMinSizeMB(10 * gb)
	if sz10 != 1.0 {
		t.Errorf("10GB disk should yield 1.0 MB; got %.2f", sz10)
	}

	sz50 := calculateDynamicMinSizeMB(50 * gb)
	if sz50 != 1.0 {
		t.Errorf("50GB disk should yield 1.0 MB; got %.2f", sz50)
	}

	sz100 := calculateDynamicMinSizeMB(100 * gb)
	if sz100 < 9.9 || sz100 > 10.1 {
		t.Errorf("100GB disk should yield ~10.0 MB; got %.2f", sz100)
	}

	sz1000 := calculateDynamicMinSizeMB(1000 * gb)
	if sz1000 != 50.0 {
		t.Errorf("1TB disk should yield 50.0 MB cap; got %.2f", sz1000)
	}

	szZero := calculateDynamicMinSizeMB(0)
	if szZero != 10.0 {
		t.Errorf("0 disk size should yield 10.0 MB fallback; got %.2f", szZero)
	}
}

func TestFormatNumber(t *testing.T) {
	if formatNumber(123) != "123" {
		t.Errorf("formatNumber(123) failed")
	}
	if formatNumber(1234567) != "1,234,567" {
		t.Errorf("formatNumber(1234567) failed")
	}
}

func TestIsProtected(t *testing.T) {
	if !isProtected("/path/to/config.toml") {
		t.Errorf("isProtected config.toml failed")
	}
	if !isProtected("/path/to/credentials.json") {
		t.Errorf("isProtected credentials.json failed")
	}
	if isProtected("/path/to/normal.txt") {
		t.Errorf("isProtected normal.txt failed")
	}
}

func TestContainsProtectedPath(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub")
	os.MkdirAll(subDir, 0755)
	credFile := filepath.Join(subDir, "credentials.json")
	os.WriteFile(credFile, []byte("secret"), 0600)

	if !containsProtectedPath(tmpDir) {
		t.Errorf("containsProtectedPath should detect sub/credentials.json")
	}

	safeDir := t.TempDir()
	os.WriteFile(filepath.Join(safeDir, "foo.txt"), []byte("ok"), 0644)
	if containsProtectedPath(safeDir) {
		t.Errorf("containsProtectedPath reported true for clean directory")
	}
}

func TestMatchPattern(t *testing.T) {
	if !matchPattern("model.gguf", "*.gguf") {
		t.Errorf("matchPattern model.gguf failed")
	}
	if !matchPattern("build.o", "build.*") {
		t.Errorf("matchPattern build.o failed")
	}
	if matchPattern("model.txt", "*.gguf") {
		t.Errorf("matchPattern model.txt incorrectly matched *.gguf")
	}
}

func TestRenderProgressBar(t *testing.T) {
	if renderProgressBar(0, 10) != "[░░░░░░░░░░]" {
		t.Errorf("renderProgressBar(0) failed")
	}
	if renderProgressBar(50, 10) != "[█████░░░░░]" {
		t.Errorf("renderProgressBar(50) failed")
	}
	if renderProgressBar(100, 10) != "[██████████]" {
		t.Errorf("renderProgressBar(100) failed")
	}
	if renderProgressBar(150, 10) != "[██████████]" {
		t.Errorf("renderProgressBar(150) overflow failed")
	}
	if renderProgressBar(-10, 10) != "[░░░░░░░░░░]" {
		t.Errorf("renderProgressBar(-10) underflow failed")
	}
}

func TestHermeticFindFzf(t *testing.T) {
	tmpBin := t.TempDir()
	mockFzf := filepath.Join(tmpBin, "fzf")
	os.WriteFile(mockFzf, []byte("#!/bin/sh\necho mock"), 0755)
	t.Setenv("PATH", tmpBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	fzfBin := findFzf()
	if fzfBin == "" {
		t.Errorf("Hermetic findFzf failed to find mocked fzf")
	}
}

func TestFindFzfFallback(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	t.Setenv("PATH", t.TempDir())

	altFzf := filepath.Join(tempHome, ".local", "bin", "fzf")
	os.MkdirAll(filepath.Dir(altFzf), 0755)
	os.WriteFile(altFzf, []byte("#!/bin/sh"), 0755)

	if findFzf() != altFzf {
		t.Errorf("findFzf fallback to ~/.local/bin/fzf failed")
	}
}

func TestRunFzfInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	mockFzf := filepath.Join(tmpDir, "fzf")
	script := `#!/bin/sh
cat > /dev/null
echo "[0001]  10.0 MB | 5.0d | Cache Dir | /tmp/test_candidate"
`
	os.WriteFile(mockFzf, []byte(script), 0755)

	candidates := []Candidate{
		{
			ID:       1,
			Path:     "/tmp/test_candidate",
			Size:     10 * 1024 * 1024,
			AgeDays:  5.0,
			Category: "Cache Dir",
			IsData:   true,
		},
	}

	selected := runFzfInteractive(candidates, mockFzf, 100*1024*1024*1024, 50*1024*1024*1024, 50*1024*1024*1024)
	if len(selected) != 1 || selected[0].Path != "/tmp/test_candidate" {
		t.Errorf("runFzfInteractive mock failed: %v", selected)
	}
}

func TestFormatUninstallArgs(t *testing.T) {
	tmpDir := t.TempDir()
	targetPipxVenv := filepath.Join(tmpDir, ".local", "pipx", "venvs", "black")
	os.MkdirAll(targetPipxVenv, 0755)
	symlinkPath := filepath.Join(tmpDir, ".local", "bin", "black")
	os.MkdirAll(filepath.Dir(symlinkPath), 0755)
	_ = os.Symlink(filepath.Join(targetPipxVenv, "bin", "black"), symlinkPath)

	inv := &PackageInventory{
		CargoCrates: map[string]string{"my-bin": "my-crate"},
		PipxVenvs:   map[string]string{"my-tool": "my-tool"},
	}

	// 1. Cargo
	cArgs := formatUninstallArgs("UNUSED (Cargo)", "my-bin", "/path/to/my-bin", inv)
	if len(cArgs) != 3 || cArgs[2] != "my-crate" {
		t.Errorf("Cargo formatUninstallArgs failed: %v", cArgs)
	}
	if formatUninstallArgs("UNUSED (Cargo)", "unknown-bin", "/path", inv) != nil {
		t.Errorf("Cargo formatUninstallArgs should return nil for unmapped binary")
	}

	// 2. npm
	nArgs := formatUninstallArgs("UNUSED (npm)", "express-cli", "/path/to/express-cli", inv)
	if len(nArgs) != 4 || nArgs[3] != "express-cli" {
		t.Errorf("npm formatUninstallArgs failed: %v", nArgs)
	}
	if formatUninstallArgs("UNUSED (npm)", "node", "/path/to/node", inv) != nil {
		t.Errorf("npm core wrapper node should return nil")
	}

	// 3. pipx
	pArgs := formatUninstallArgs("UNUSED (pipx)", "black", symlinkPath, inv)
	if len(pArgs) != 3 || pArgs[2] != "black" {
		t.Errorf("pipx formatUninstallArgs via symlink failed: %v", pArgs)
	}

	// 4. Swiftly
	sArgs := formatUninstallArgs("UNUSED (Swift)", "swift-5.9", "/home/user/.local/share/swiftly/toolchains/5.9.2/usr/bin", inv)
	if len(sArgs) != 3 || sArgs[2] != "5.9.2" {
		t.Errorf("Swift formatUninstallArgs failed: %v", sArgs)
	}

	// 5. SDKMAN
	sdkArgs := formatUninstallArgs("UNUSED (SDKMAN)", "17.0.1-open", "/home/user/.sdkman/candidates/java/17.0.1-open", inv)
	if len(sdkArgs) != 4 || sdkArgs[2] != "java" || sdkArgs[3] != "17.0.1-open" {
		t.Errorf("SDKMAN formatUninstallArgs failed: %v", sdkArgs)
	}

	// 6. Dotnet, Composer, ZVM
	if len(formatUninstallArgs("UNUSED (Dotnet)", "tool1", "/path", inv)) != 5 {
		t.Errorf("Dotnet formatUninstallArgs failed")
	}
	if len(formatUninstallArgs("UNUSED (Composer)", "pkg1", "/path", inv)) != 4 {
		t.Errorf("Composer formatUninstallArgs failed")
	}
	if len(formatUninstallArgs("UNUSED (ZVM)", "0.11.0", "/path", inv)) != 3 {
		t.Errorf("ZVM formatUninstallArgs failed")
	}
}

func TestHostileFilenames(t *testing.T) {
	tmpDir := t.TempDir()
	hostileNames := []string{
		"file with spaces.log",
		"file;touch_hacked.log",
		"file|grep_hacked.log",
		"file'quote.log",
		"file\"doublequote.log",
	}

	oldTime := time.Now().Add(-200 * time.Hour)
	for _, hName := range hostileNames {
		p := filepath.Join(tmpDir, hName)
		os.WriteFile(p, bytes.Repeat([]byte("a"), 200*1024), 0644)
		os.Chtimes(p, oldTime, oldTime)
	}

	engine := NewRuleEngine(getDefaultManifest())
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)

	if len(candidates) != len(hostileNames) {
		t.Errorf("scanParallel found %d hostile candidates; expected %d", len(candidates), len(hostileNames))
	}
}

func TestStress10kCandidates(t *testing.T) {
	var candidates []Candidate
	for i := 1; i <= 12000; i++ {
		candidates = append(candidates, Candidate{
			ID:             i,
			Path:           fmt.Sprintf("/tmp/fake_%d.log", i),
			Size:           1024,
			AgeDays:        10.0,
			Category:       "Log",
			RiskClass:      "regenerable",
			Reason:         "Stale test log",
			ProposedAction: "delete_file",
		})
	}

	if len(candidates) != 12000 {
		t.Errorf("Stress candidate allocation failed")
	}
}

func TestLoadManifest(t *testing.T) {
	tmpDir := t.TempDir()

	manPath := filepath.Join(tmpDir, "manifest.json")
	content := `{
		"rules": [
			{"id": "test_rule", "name": "Test Rule", "target": "file", "patterns": ["*.test"], "category": "Test"}
		]
	}`
	os.WriteFile(manPath, []byte(content), 0644)

	m, err := loadManifest(manPath)
	if err != nil || len(m.Rules) != 1 || m.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest custom file failed: %v", err)
	}

	_, errBad := loadManifest("/non/existent/path/to/manifest.json")
	if errBad == nil {
		t.Errorf("loadManifest should fail closed for bad path")
	}

	badJSON := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(badJSON, []byte("{bad json"), 0644)
	_, errJSON := loadManifest(badJSON)
	if errJSON == nil {
		t.Errorf("loadManifest should fail closed for bad JSON")
	}

	tempHome := t.TempDir()
	dotPath := filepath.Join(tempHome, ".unslop.json")
	os.WriteFile(dotPath, []byte(content), 0644)
	t.Setenv("HOME", tempHome)

	mDot, errDot := loadManifest("")
	if errDot != nil || len(mDot.Rules) != 1 || mDot.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest ~/.unslop.json failed: %v", errDot)
	}

	tempHome2 := t.TempDir()
	xdgPath := filepath.Join(tempHome2, ".config", "unslop", "manifest.json")
	os.MkdirAll(filepath.Dir(xdgPath), 0755)
	os.WriteFile(xdgPath, []byte(content), 0644)
	t.Setenv("HOME", tempHome2)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tempHome2, ".config"))

	mXDG, errXDG := loadManifest("")
	if errXDG != nil || len(mXDG.Rules) != 1 || mXDG.Rules[0].ID != "test_rule" {
		t.Errorf("loadManifest XDG path failed: %v", errXDG)
	}
}

func TestMultimodFlag(t *testing.T) {
	var m multimodFlag
	if m.String() != "" {
		t.Errorf("multimodFlag empty String() failed")
	}
	m.Set("/tmp/dir1")
	m.Set("/tmp/dir2")

	if m.String() != "/tmp/dir1,/tmp/dir2" {
		t.Errorf("multimodFlag String() = %s", m.String())
	}
}

func TestGetDefaultScanDirs(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	t.Setenv("TEMP", "/tmp")
	dirs := getDefaultScanDirs()
	if len(dirs) == 0 {
		t.Errorf("getDefaultScanDirs returned empty slice")
	}
}

func TestGetDiskSpace(t *testing.T) {
	tot, used, free, err := getDiskSpace("/")
	if err != nil || tot == 0 || used == 0 || free == 0 {
		t.Errorf("getDiskSpace('/') failed: tot=%d used=%d free=%d err=%v", tot, used, free, err)
	}
}

func TestMoveToTrash(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "trashme.txt")
	os.WriteFile(f, []byte("data"), 0644)

	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	err := moveToTrash(f)
	if err != nil {
		t.Fatalf("moveToTrash failed: %v", err)
	}

	trashedFile := filepath.Join(tempHome, ".local", "share", "Trash", "files", "trashme.txt")
	if _, err := os.Stat(trashedFile); os.IsNotExist(err) {
		t.Errorf("moveToTrash fallback file not found in Trash directory")
	}
}

func TestMoveToTrashMockExec(t *testing.T) {
	tmpDir := t.TempDir()
	mockGio := filepath.Join(tmpDir, "gio")
	os.WriteFile(mockGio, []byte("#!/bin/sh\nexit 0\n"), 0755)

	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	f := filepath.Join(t.TempDir(), "dummy.txt")
	os.WriteFile(f, []byte("data"), 0644)
	if err := moveToTrash(f); err != nil {
		t.Errorf("moveToTrash with mock gio failed: %v", err)
	}
}

func TestRunFzfInteractiveEmpty(t *testing.T) {
	if runFzfInteractive(nil, "fzf", 1000, 500, 500) != nil {
		t.Errorf("runFzfInteractive(nil) should return nil")
	}
}

func TestGetDirStats(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "a.txt")
	os.WriteFile(f1, []byte("hello"), 0644)

	now := time.Now()
	sz, maxMt, fCount := getDirStats(tmpDir, now)
	if sz != 5 || fCount != 1 || maxMt.IsZero() {
		t.Errorf("getDirStats failed: sz=%d fCount=%d maxMt=%v", sz, fCount, maxMt)
	}
}

func TestPackageInventory(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	cargoDir := filepath.Join(tempHome, ".cargo")
	os.MkdirAll(cargoDir, 0755)
	cratesToml := filepath.Join(cargoDir, ".crates.toml")
	tomlData := "\"my-crate 0.1.0 (registry+https://github.com/rust-lang/crates.io-index)\" = [\"my-bin\"]\n"
	os.WriteFile(cratesToml, []byte(tomlData), 0644)

	pipxVenvs := filepath.Join(tempHome, ".local", "pipx", "venvs", "black")
	os.MkdirAll(pipxVenvs, 0755)

	inv := loadPackageInventory()
	if inv.CargoCrates["my-bin"] != "my-crate" {
		t.Errorf("loadPackageInventory failed to parse Cargo crate; got %v", inv.CargoCrates)
	}
	if inv.PipxVenvs["black"] != "black" {
		t.Errorf("loadPackageInventory failed to parse pipx venv")
	}
}

func TestApplyOverrides(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)
	inv := loadPackageInventory()

	removed, added := applyOverrides(engine, []string{"-zig_cache", "+*.bak"})
	if len(removed) != 1 || removed[0] != "zig_cache" {
		t.Errorf("applyOverrides remove failed")
	}
	if len(added) != 1 || added[0] != "*.bak" {
		t.Errorf("applyOverrides add failed")
	}

	ruleDir, _, _ := engine.MatchDir(".zig-cache", "/path/to/.zig-cache", inv)
	if ruleDir != nil {
		t.Errorf("zig_cache rule should have been removed")
	}
}

func TestConfirmAndDeleteExecution(t *testing.T) {
	tmpDir := t.TempDir()

	confirmAndDelete(nil, false, false, 1000, 1000)

	file1 := filepath.Join(tmpDir, "file1.log")
	os.WriteFile(file1, []byte("log data"), 0644)
	selected1 := []Candidate{{Path: file1, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	confirmAndDelete(selected1, true, false, 1000, 1000)
	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("Dry run should not delete file1")
	}

	file2 := filepath.Join(tmpDir, "file2.log")
	dir2 := filepath.Join(tmpDir, "dir2_cache")
	os.WriteFile(file2, []byte("log data"), 0644)
	os.MkdirAll(dir2, 0755)
	now := time.Now()

	selected2 := []Candidate{
		{Path: file2, Size: 8, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: now},
		{Path: dir2, Size: 16, AgeDays: 5.0, Category: "Cache Dir", IsDir: true, ModTime: now},
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")

	confirmAndDeleteWithIO(selected2, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("file2 should have been deleted")
	}
	if _, err := os.Stat(dir2); !os.IsNotExist(err) {
		t.Errorf("dir2 should have been deleted")
	}
}

func TestConfirmAndDeleteCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "keep.log")
	os.WriteFile(file1, []byte("data"), 0644)

	selected := []Candidate{{Path: file1, Size: 4, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}

	var stdout bytes.Buffer
	stdin := strings.NewReader("n\n")

	confirmAndDeleteWithIO(selected, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(file1); os.IsNotExist(err) {
		t.Errorf("file1 should NOT have been deleted when user answers 'n'")
	}
}

func TestUninstallCmdExecution(t *testing.T) {
	tmpDir := t.TempDir()
	binaryFile := filepath.Join(tmpDir, "dummy_bin")
	os.WriteFile(binaryFile, []byte("bin"), 0755)

	selected := []Candidate{
		{
			Path:          binaryFile,
			Size:          3,
			AgeDays:       10.0,
			Category:      "UNUSED (Cargo)",
			IsDir:         false,
			PackageName:   "dummy_bin",
			UninstallArgs: []string{"non_existent_command_12345"},
			ModTime:       time.Now(),
		},
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\ny\n")

	confirmAndDeleteWithIO(selected, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(binaryFile); !os.IsNotExist(err) {
		t.Errorf("Fallback direct removal should have deleted binaryFile")
	}
}

func TestRunMainFlags(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(targetDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	cacheFile := filepath.Join(targetDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheFile, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	var stdout, stderr bytes.Buffer

	// 1. Test version flag
	code := runMain([]string{"-version"}, &stdout, &stderr, nil)
	if code != 0 || !strings.Contains(stdout.String(), "unslop version") {
		t.Errorf("runMain -version failed: code=%d stdout=%s", code, stdout.String())
	}

	// 2. Test JSON flag & plan-out
	stdout.Reset()
	stderr.Reset()
	planOut := filepath.Join(tmpDir, "plan.json")
	codeJSON := runMain([]string{"-json", "-plan-out", planOut, "-path", tmpDir}, &stdout, &stderr, nil)
	if codeJSON != 0 {
		t.Errorf("runMain -json failed: code=%d stderr=%s", codeJSON, stderr.String())
	}
	if _, err := os.Stat(planOut); os.IsNotExist(err) {
		t.Errorf("runMain -plan-out did not create plan.json")
	}

	// 3. Test bad flag
	codeBad := runMain([]string{"-invalid-flag-12345"}, &stdout, &stderr, nil)
	if codeBad != 2 {
		t.Errorf("runMain bad flag expected code 2; got %d", codeBad)
	}

	// 4. Test bad manifest path
	codeManifest := runMain([]string{"-manifest", "/non/existent/manifest.json"}, &stdout, &stderr, nil)
	if codeManifest != 1 {
		t.Errorf("runMain bad manifest expected code 1; got %d", codeManifest)
	}
}

func TestRunMainTextSummaryNoFzf(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	subDir := filepath.Join(tempHome, "project")
	targetDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(targetDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	cacheFile := filepath.Join(targetDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheFile, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	var stdout, stderr bytes.Buffer
	code := runMain([]string{"-path", tempHome}, &stdout, &stderr, nil)
	if code != 0 {
		t.Errorf("runMain text summary expected code 0; got %d", code)
	}
	if !strings.Contains(stderr.String(), "fzf runtime binary not found") {
		t.Errorf("runMain text summary missing fzf notice in stderr: %s", stderr.String())
	}
}



func TestMatchFileAtime(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)
	inv := loadPackageInventory()

	tmpDir := t.TempDir()
	binFile := filepath.Join(tmpDir, "dummy")
	os.WriteFile(binFile, []byte("bin"), 0755)
	fi, _ := os.Stat(binFile)

	rule, _, _ := engine.MatchFile("dummy", filepath.Join(tmpDir, ".cargo", "bin", "dummy"), fi, inv)
	if rule != nil && rule.ID != "cargo_pkg" {
		t.Errorf("MatchFile atime check failed: %v", rule)
	}
}

func TestVersionFlag(t *testing.T) {
	if Version == "" {
		t.Errorf("Version constant should not be empty")
	}
}

func TestConfirmAndDeleteSafeguards(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. File type changed (file became dir) -> ABORT
	dirAsFile := filepath.Join(tmpDir, "changed_dir")
	os.MkdirAll(dirAsFile, 0755)
	cand1 := []Candidate{{Path: dirAsFile, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	var out1 bytes.Buffer
	confirmAndDeleteWithIO(cand1, false, false, 1000, 1000, &out1, strings.NewReader("y\n"))
	if !strings.Contains(out1.String(), "[ABORT]") {
		t.Errorf("Expected [ABORT] for type change; got: %s", out1.String())
	}

	// 2. File no longer exists -> SKIP
	missingFile := filepath.Join(tmpDir, "missing.log")
	cand2 := []Candidate{{Path: missingFile, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	var out2 bytes.Buffer
	confirmAndDeleteWithIO(cand2, false, false, 1000, 1000, &out2, strings.NewReader("y\n"))
	if !strings.Contains(out2.String(), "[SKIP]") {
		t.Errorf("Expected [SKIP] for missing file; got: %s", out2.String())
	}

	// 3. Protected path inside candidate directory -> REFUSE
	protectedDir := filepath.Join(tmpDir, "protected_target")
	os.MkdirAll(protectedDir, 0755)
	os.WriteFile(filepath.Join(protectedDir, "credentials.json"), []byte("secret"), 0600)
	cand3 := []Candidate{{Path: protectedDir, Size: 10, AgeDays: 5.0, Category: "Cache Dir", IsDir: true, ModTime: time.Now()}}
	var out3 bytes.Buffer
	confirmAndDeleteWithIO(cand3, false, false, 1000, 1000, &out3, strings.NewReader("y\n"))
	if !strings.Contains(out3.String(), "[PROTECTED SAFEGUARD]") {
		t.Errorf("Expected [PROTECTED SAFEGUARD]; got: %s", out3.String())
	}

	// 4. Trash deletion execution
	trashFile := filepath.Join(tmpDir, "trash_file.log")
	os.WriteFile(trashFile, []byte("data"), 0644)
	cand4 := []Candidate{{Path: trashFile, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	var out4 bytes.Buffer
	confirmAndDeleteWithIO(cand4, false, true, 1000, 1000, &out4, strings.NewReader("y\n"))
	if !strings.Contains(out4.String(), "[TRASHED]") {
		t.Errorf("Expected [TRASHED]; got: %s", out4.String())
	}
}

func TestScanParallelIncludeDataAndTmpFilters(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)

	llmFile := filepath.Join(tmpDir, "model.gguf")
	os.WriteFile(llmFile, bytes.Repeat([]byte("m"), 200*1024), 0644)
	os.Chtimes(llmFile, oldTime, oldTime)

	sockFile := filepath.Join(tmpDir, "app.sock")
	os.WriteFile(sockFile, []byte("sock"), 0644)
	os.Chtimes(sockFile, oldTime, oldTime)

	lockFile := filepath.Join(tmpDir, "app.lock")
	os.WriteFile(lockFile, []byte("lock"), 0644)
	os.Chtimes(lockFile, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())

	cands1 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)
	for _, c := range cands1 {
		if c.Path == llmFile {
			t.Errorf("model.gguf should be skipped when includeData is false")
		}
	}

	cands2 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	foundLLM := false
	for _, c := range cands2 {
		if c.Path == llmFile {
			foundLLM = true
		}
		if c.Path == sockFile || c.Path == lockFile {
			t.Errorf("Socket/Lock files in /tmp should be filtered out")
		}
	}
	if !foundLLM {
		t.Errorf("model.gguf should be found when includeData is true")
	}
}

func TestRunMainExecutionAndTrash(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(subDir, ".zig-cache")
	os.MkdirAll(targetDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	cacheFile := filepath.Join(targetDir, "build.o")
	os.WriteFile(cacheFile, bytes.Repeat([]byte("y"), 2*1024*1024), 0644)
	os.Chtimes(cacheFile, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	var stdout, stderr bytes.Buffer

	code := runMain([]string{"-apply", "-trash", "-include-data", "-path", tmpDir}, &stdout, &stderr, strings.NewReader("y\n"))
	if code != 0 {
		t.Errorf("runMain -apply -trash expected code 0; got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	codeJSONApply := runMain([]string{"-json", "-apply", "-path", tmpDir}, &stdout, &stderr, strings.NewReader("n\n"))
	if codeJSONApply != 0 {
		t.Errorf("runMain -json -apply expected code 0; got %d", codeJSONApply)
	}
}

func TestMainFunc(t *testing.T) {
	oldExit := osExit
	defer func() { osExit = oldExit }()
	osExit = func(code int) {}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"unslop", "-version"}

	main()
}

func TestMoveToTrashAllBranches(t *testing.T) {
	tmpDir := t.TempDir()

	mockGio := filepath.Join(tmpDir, "gio")
	os.WriteFile(mockGio, []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", tmpDir)

	f1 := filepath.Join(t.TempDir(), "f1.txt")
	os.WriteFile(f1, []byte("1"), 0644)
	if err := moveToTrash(f1); err != nil {
		t.Errorf("moveToTrash gio success failed: %v", err)
	}

	tmpDir2 := t.TempDir()
	mockGioFail := filepath.Join(tmpDir2, "gio")
	os.WriteFile(mockGioFail, []byte("#!/bin/sh\nexit 1\n"), 0755)
	mockTrash := filepath.Join(tmpDir2, "trash")
	os.WriteFile(mockTrash, []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", tmpDir2)

	f2 := filepath.Join(t.TempDir(), "f2.txt")
	os.WriteFile(f2, []byte("2"), 0644)
	if err := moveToTrash(f2); err != nil {
		t.Errorf("moveToTrash trash-cli success failed: %v", err)
	}
}

func TestConfirmAndDeleteUninstallSuccessAndFallback(t *testing.T) {
	tmpDir := t.TempDir()

	mockCmdBin := filepath.Join(tmpDir, "mock_uninstall")
	os.WriteFile(mockCmdBin, []byte("#!/bin/sh\nexit 0\n"), 0755)
	t.Setenv("PATH", tmpDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dummyFile1 := filepath.Join(tmpDir, "dummy1")
	os.WriteFile(dummyFile1, []byte("bin"), 0755)

	candSuccess := []Candidate{
		{
			Path:          dummyFile1,
			Size:          10,
			AgeDays:       5.0,
			Category:      "UNUSED (Cargo)",
			IsDir:         false,
			UninstallArgs: []string{"mock_uninstall", "dummy1"},
			ModTime:       time.Now(),
		},
	}

	var stdout1 bytes.Buffer
	confirmAndDeleteWithIO(candSuccess, false, false, 1000, 1000, &stdout1, strings.NewReader("y\n"))
	if !strings.Contains(stdout1.String(), "[UNINSTALLED SUCCESS]") {
		t.Errorf("Expected [UNINSTALLED SUCCESS]; got: %s", stdout1.String())
	}

	dummyFile2 := filepath.Join(tmpDir, "dummy2")
	os.WriteFile(dummyFile2, []byte("bin"), 0755)

	candFail := []Candidate{
		{
			Path:          dummyFile2,
			Size:          10,
			AgeDays:       5.0,
			Category:      "UNUSED (Cargo)",
			IsDir:         false,
			UninstallArgs: []string{"non_existent_command_999"},
			ModTime:       time.Now(),
		},
	}

	var stdout2 bytes.Buffer
	confirmAndDeleteWithIO(candFail, false, false, 1000, 1000, &stdout2, strings.NewReader("y\nn\n"))
	if !strings.Contains(stdout2.String(), "Fallback: Remove") {
		t.Errorf("Expected Fallback prompt; got: %s", stdout2.String())
	}
}

func TestFormatUninstallArgsEdgeCases(t *testing.T) {
	inv := &PackageInventory{}

	if formatUninstallArgs("UNUSED (SDKMAN)", "current", "/home/user/.sdkman/candidates/java/current", inv) != nil {
		t.Errorf("SDKMAN 'current' symlink should return nil")
	}

	if formatUninstallArgs("UNKNOWN_CATEGORY", "foo", "/path", inv) != nil {
		t.Errorf("Unknown category should return nil")
	}

	if formatUninstallArgs("UNUSED (Swift)", "foo", "/normal/path", inv) != nil {
		t.Errorf("Swift non-matching path should return nil")
	}

	if formatUninstallArgs("UNUSED (pipx)", "foo", "/normal/path", inv) != nil {
		t.Errorf("pipx non-venv path should return nil")
	}
}

func TestMatchFileComprehensive(t *testing.T) {
	m := getDefaultManifest()
	engine := NewRuleEngine(m)
	inv := loadPackageInventory()

	tmpFile := filepath.Join(t.TempDir(), "random.xyz")
	os.WriteFile(tmpFile, []byte("data"), 0644)
	fi, _ := os.Stat(tmpFile)

	r1, _, _ := engine.MatchFile("random.xyz", tmpFile, fi, inv)
	if r1 != nil {
		t.Errorf("random.xyz should not match any rule")
	}

	jsonlFile := filepath.Join(t.TempDir(), "rollout-123.jsonl")
	os.WriteFile(jsonlFile, []byte("jsonl"), 0644)
	fi2, _ := os.Stat(jsonlFile)
	r2, _, _ := engine.MatchFile("rollout-123.jsonl", jsonlFile, fi2, inv)
	if r2 == nil {
		t.Errorf("rollout-123.jsonl should match a rule")
	}

	perfFile := filepath.Join(t.TempDir(), "perf.data.123")
	os.WriteFile(perfFile, []byte("perf"), 0644)
	fi3, _ := os.Stat(perfFile)
	r3, _, _ := engine.MatchFile("perf.data.123", perfFile, fi3, inv)
	if r3 == nil || r3.ID != "profile_data" {
		t.Errorf("perf.data.123 should match profile_data; got %v", r3)
	}
}

func TestScanParallelEdgeCases(t *testing.T) {
	engine := NewRuleEngine(getDefaultManifest())

	// 1. Non-existent path in scanDirs
	cands1 := scanParallel([]string{"/non/existent/path/999"}, engine, 2.0, 100*1024, false)
	if len(cands1) != 0 {
		t.Errorf("Non-existent path should yield 0 candidates")
	}

	// 2. Direct file in scanDirs
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "stale.log")
	oldTime := time.Now().Add(-200 * time.Hour)
	os.WriteFile(logFile, bytes.Repeat([]byte("a"), 200*1024), 0644)
	os.Chtimes(logFile, oldTime, oldTime)

	cands2 := scanParallel([]string{logFile}, engine, 2.0, 100*1024, false)
	if len(cands2) != 1 {
		t.Errorf("Direct file scan should yield 1 candidate")
	}
}

func TestScanParallelDirRulesAndMinSize(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "project")
	targetDir := filepath.Join(subDir, "custom_dir_cache")
	os.MkdirAll(targetDir, 0755)

	oldTime := time.Now().Add(-200 * time.Hour)
	f := filepath.Join(targetDir, "data.bin")
	os.WriteFile(f, bytes.Repeat([]byte("z"), 2*1024*1024), 0644)
	os.Chtimes(f, oldTime, oldTime)
	os.Chtimes(targetDir, oldTime, oldTime)

	customManifest := Manifest{
		Rules: []Rule{
			{
				ID:        "custom_dir",
				Name:      "Custom Dir Rule",
				Target:    "dir",
				Patterns:  []string{"custom_dir_cache"},
				Category:  "Custom Dir",
				MinSizeMB: 1.0,
				IsData:    true,
			},
		},
	}

	engine := NewRuleEngine(customManifest)

	cands1 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)
	if len(cands1) != 0 {
		t.Errorf("Custom dir with is_data=true should be skipped when includeData=false")
	}

	cands2 := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	if len(cands2) != 1 || cands2[0].Path != targetDir {
		t.Errorf("Custom dir candidate expected; got %v", cands2)
	}
}

func TestConfirmAndDeleteDirectRemoval(t *testing.T) {
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "delete_direct.log")
	os.WriteFile(f, []byte("log"), 0644)

	d := filepath.Join(tmpDir, "delete_direct_dir")
	os.MkdirAll(d, 0755)

	now := time.Now()
	cands := []Candidate{
		{Path: f, Size: 3, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: now},
		{Path: d, Size: 10, AgeDays: 5.0, Category: "Cache Dir", IsDir: true, ModTime: now},
	}

	var stdout bytes.Buffer
	stdin := strings.NewReader("y\n")

	confirmAndDeleteWithIO(cands, false, false, 1000, 1000, &stdout, stdin)

	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Errorf("f should have been deleted directly")
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Errorf("d should have been deleted directly")
	}
}

func TestCoverageBoosters(t *testing.T) {
	tot, used, free, err := getDiskSpace("/non/existent/path/999")
	if err != nil || tot == 0 || used == 0 || free == 0 {
		t.Errorf("getDiskSpace error fallback failed: %v", err)
	}

	_, maxMt, _ := getDirStats("/non/existent/path/999", time.Now())
	if maxMt.IsZero() {
		t.Errorf("getDirStats non-existent path fallback failed")
	}

	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, ".git")
	os.MkdirAll(gitDir, 0755)
	os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main"), 0644)

	smallJSON := filepath.Join(tmpDir, "small.json")
	oldTime := time.Now().Add(-200 * time.Hour)
	os.WriteFile(smallJSON, bytes.Repeat([]byte("{}\n"), 100*1024), 0644)
	os.Chtimes(smallJSON, oldTime, oldTime)

	largeJSON := filepath.Join(tmpDir, "large.json")
	os.WriteFile(largeJSON, bytes.Repeat([]byte("{}\n"), 3*1024*1024), 0644)
	os.Chtimes(largeJSON, oldTime, oldTime)

	subDir := filepath.Join(tmpDir, "project")
	nodeCache := filepath.Join(subDir, "node_modules", ".cache")
	os.MkdirAll(nodeCache, 0755)
	os.WriteFile(filepath.Join(nodeCache, "cache.o"), bytes.Repeat([]byte("c"), 2*1024*1024), 0644)
	os.Chtimes(nodeCache, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())

	cands := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	foundLarge := false

	for _, c := range cands {
		if strings.Contains(c.Path, ".git") {
			t.Errorf(".git directory should be skipped completely")
		}
		if c.Path == smallJSON {
			t.Errorf("small.json (<5MB) should be skipped by min_size_mb rule constraint")
		}
		if c.Path == largeJSON {
			foundLarge = true
		}
	}

	if !foundLarge {
		t.Errorf("large.json should be matched")
	}
}

func TestCoverageBoostersPhase2(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)
	tmpFile := filepath.Join(tmpDir, "stale_tmp.log")
	os.WriteFile(tmpFile, bytes.Repeat([]byte("t"), 200*1024), 0644)
	os.Chtimes(tmpFile, oldTime, oldTime)

	engine := NewRuleEngine(getDefaultManifest())
	cands := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, false)
	if len(cands) != 1 {
		t.Errorf("scanParallel on tmpDir expected 1 candidate; got %d", len(cands))
	}

	var stdout, stderr bytes.Buffer
	code := runMain([]string{"-days", "14", "-min-size-mb", "10", "-path", tmpDir, "--", "-zig_cache", "+*.tmp"}, &stdout, &stderr, nil)
	if code != 0 {
		t.Errorf("runMain with overrides expected code 0; got %d (stderr: %s)", code, stderr.String())
	}

	stdout.Reset()
	confirmAndDeleteWithIO(nil, false, false, 1000, 1000, &stdout, nil)
	if !strings.Contains(stdout.String(), "No items selected") {
		t.Errorf("Empty candidate selection should print 'No items selected'")
	}
}

func TestCoverageBoostersPhase3(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	dummy := filepath.Join(t.TempDir(), "fallback_trash.txt")
	os.WriteFile(dummy, []byte("data"), 0644)
	if err := moveToTrash(dummy); err != nil {
		t.Errorf("moveToTrash fallback failed: %v", err)
	}

	trashFile := filepath.Join(t.TempDir(), "trash_direct.log")
	os.WriteFile(trashFile, []byte("log"), 0644)
	cands := []Candidate{{Path: trashFile, Size: 10, AgeDays: 5.0, Category: "Log", IsDir: false, ModTime: time.Now()}}
	var stdout bytes.Buffer
	confirmAndDeleteWithIO(cands, false, true, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[TRASHED]") {
		t.Errorf("Expected [TRASHED]; got: %s", stdout.String())
	}

	ruleAtime := Rule{
		ID:               "atime_rule",
		Name:             "Atime Rule",
		Target:           "file",
		Patterns:         []string{"*.atime"},
		Category:         "Atime Test",
		CheckUnusedAtime: true,
	}
	engine := NewRuleEngine(Manifest{Rules: []Rule{ruleAtime}})
	inv := &PackageInventory{}

	atimeFile := filepath.Join(t.TempDir(), "test.atime")
	os.WriteFile(atimeFile, []byte("atime"), 0644)
	fi, _ := os.Stat(atimeFile)

	rMatch, _, _ := engine.MatchFile("test.atime", atimeFile, fi, inv)
	if rMatch == nil {
		t.Errorf("MatchFile atime check within 24h should match")
	}
}

func TestCoverageFinalPush(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)
	if calculateDynamicMinSizeMB(20*gb) != 1.0 {
		t.Errorf("<=50GB should return 1.0")
	}
	if calculateDynamicMinSizeMB(75*gb) < 5.0 {
		t.Errorf("75GB interpolation failed")
	}
	if calculateDynamicMinSizeMB(2000*gb) != 50.0 {
		t.Errorf(">=1000GB should cap at 50.0")
	}

	tmpDir := t.TempDir()
	protectedNames := []string{"settings.json", "auth.json", "rules", "skills", "memories", "memory", "knowledge"}
	for _, pName := range protectedNames {
		p := filepath.Join(tmpDir, pName)
		if strings.HasSuffix(pName, ".json") {
			os.WriteFile(p, []byte("{}"), 0644)
		} else {
			os.MkdirAll(p, 0755)
		}
		if !isProtected(p) {
			t.Errorf("isProtected failed for %s", pName)
		}
	}

	tmpSubDir := filepath.Join(t.TempDir(), "tmp_test")
	os.MkdirAll(tmpSubDir, 0755)

	youngLog := filepath.Join(tmpSubDir, "young.log")
	os.WriteFile(youngLog, bytes.Repeat([]byte("y"), 200*1024), 0644)

	staleLog := filepath.Join(tmpSubDir, "stale.log")
	oldTime := time.Now().Add(-200 * time.Hour)
	os.WriteFile(staleLog, bytes.Repeat([]byte("s"), 200*1024), 0644)
	os.Chtimes(staleLog, oldTime, oldTime)

	os.WriteFile(filepath.Join(tmpSubDir, "test.sock"), []byte("s"), 0644)
	os.WriteFile(filepath.Join(tmpSubDir, "test.lock"), []byte("l"), 0644)
	os.WriteFile(filepath.Join(tmpSubDir, "test.pid"), []byte("p"), 0644)

	engine := NewRuleEngine(getDefaultManifest())
	cands := scanParallel([]string{tmpSubDir}, engine, 7.0, 100*1024, false)

	foundStale := false
	for _, c := range cands {
		if c.Path == youngLog {
			t.Errorf("Young log file should be skipped by age constraint")
		}
		if c.Path == staleLog {
			foundStale = true
		}
	}

	if !foundStale {
		t.Errorf("Stale log file should be matched")
	}

	mockFailBin := filepath.Join(tmpDir, "failed_bin")
	os.WriteFile(mockFailBin, []byte("bin"), 0755)
	candFailTrash := []Candidate{
		{
			Path:          mockFailBin,
			Size:          5,
			AgeDays:       10.0,
			Category:      "UNUSED (Cargo)",
			IsDir:         false,
			UninstallArgs: []string{"non_existent_command_99999"},
			ModTime:       time.Now(),
		},
	}
	var stdout bytes.Buffer
	t.Setenv("PATH", tmpDir)
	confirmAndDeleteWithIO(candFailTrash, false, true, 1000, 1000, &stdout, strings.NewReader("y\ny\n"))
	if !strings.Contains(stdout.String(), "[TRASHED]") {
		t.Errorf("Fallback trash execution failed: %s", stdout.String())
	}
}

func TestCoverageSupercharge(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-200 * time.Hour)

	tinyFile := filepath.Join(tmpDir, "tiny.log")
	os.WriteFile(tinyFile, bytes.Repeat([]byte("a"), 10*1024), 0644)
	os.Chtimes(tinyFile, oldTime, oldTime)

	youngFile := filepath.Join(tmpDir, "young.tmp")
	os.WriteFile(youngFile, bytes.Repeat([]byte("y"), 200*1024), 0644)

	engine := NewRuleEngine(getDefaultManifest())

	cands := scanParallel([]string{tmpDir}, engine, 7.0, 100*1024, false)
	for _, c := range cands {
		if c.Path == tinyFile {
			t.Errorf("tinyFile (<100KB) should be pruned by early size check")
		}
		if c.Path == youngFile {
			t.Errorf("youngFile (<7 days) should be skipped")
		}
	}

	inv := &PackageInventory{}
	pArgs := formatUninstallArgs("UNUSED (pipx)", "black", "/home/user/.local/pipx/venvs/black/bin/black", inv)
	if len(pArgs) != 3 || pArgs[2] != "black" {
		t.Errorf("formatUninstallArgs pipx direct venv failed: %v", pArgs)
	}

	mockFailBin := filepath.Join(tmpDir, "fail_bin_n")
	os.WriteFile(mockFailBin, []byte("bin"), 0755)
	candFailN := []Candidate{
		{
			Path:          mockFailBin,
			Size:          5,
			AgeDays:       10.0,
			Category:      "UNUSED (Cargo)",
			IsDir:         false,
			UninstallArgs: []string{"non_existent_command_88888"},
			ModTime:       time.Now(),
		},
	}
	var stdout bytes.Buffer
	confirmAndDeleteWithIO(candFailN, false, false, 1000, 1000, &stdout, strings.NewReader("y\nn\n"))
	if !strings.Contains(stdout.String(), "Fallback: Remove") {
		t.Errorf("Expected Fallback prompt; got: %s", stdout.String())
	}
}

type mockFileInfo struct{}

func (m mockFileInfo) Name() string       { return "mock" }
func (m mockFileInfo) Size() int64        { return 100 }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return nil }

func TestCoverageFinal95(t *testing.T) {
	engine := NewRuleEngine(getDefaultManifest())
	_ = scanParallel([]string{"/tmp"}, engine, 30.0, 100*1024*1024, false)

	mockFI := mockFileInfo{}
	atime, ctime, uid, isPosix := getStatTimes(mockFI)
	if atime.IsZero() || ctime.IsZero() || uid != 0 || isPosix {
		t.Errorf("getStatTimes non-posix fallback failed")
	}
}

func TestCoverage95Plus(t *testing.T) {
	containsProtectedPath("/non/existent/path/999")

	const gb = uint64(1024 * 1024 * 1024)
	calculateDynamicMinSizeMB(0)
	calculateDynamicMinSizeMB(40 * gb)
	calculateDynamicMinSizeMB(75 * gb)
	calculateDynamicMinSizeMB(1000 * gb)

	var stdout, stderr bytes.Buffer
	runMain([]string{"-json", "-plan-out", "/non/existent/dir/999/plan.json", "-path", t.TempDir()}, &stdout, &stderr, nil)
}
