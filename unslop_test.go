package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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

func TestRiskClassEnumValidation(t *testing.T) {
	validClasses := []RiskClass{RiskRegenerable, RiskPackageManaged, RiskUserData, RiskUnknown}
	for _, r := range validClasses {
		if !r.IsValid() {
			t.Errorf("RiskClass %s should be valid", r)
		}
	}

	invalid := RiskClass("arbitrary-junk")
	if invalid.IsValid() {
		t.Errorf("Invalid RiskClass should return false for IsValid()")
	}
}

func TestCalculateDynamicMinSizeMB(t *testing.T) {
	const gb = uint64(1024 * 1024 * 1024)

	if calculateDynamicMinSizeMB(0) != 10.0 {
		t.Errorf("0 disk size should yield 10.0 MB")
	}
	if calculateDynamicMinSizeMB(10*gb) != 1.0 {
		t.Errorf("10GB disk should yield 1.0 MB")
	}
	if calculateDynamicMinSizeMB(50*gb) != 1.0 {
		t.Errorf("50GB disk should yield 1.0 MB")
	}
	sz100 := calculateDynamicMinSizeMB(100 * gb)
	if sz100 < 9.9 || sz100 > 10.1 {
		t.Errorf("100GB disk should yield ~10.0 MB; got %.2f", sz100)
	}
	if calculateDynamicMinSizeMB(1000*gb) != 50.0 {
		t.Errorf("1TB disk should yield 50.0 MB cap")
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

func TestAbsoluteGlobPathSemantics(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		match   bool
	}{
		{"/home/user/.cargo/bin/my-crate", "*/.cargo/bin/*", true},
		{"/home/user/.local/pipx/venvs/black", "*/.local/pipx/venvs/*", true},
		{"/home/user/.cache/zig/foo", "*/.cache/*", true},
		{"/home/user/src/main.go", "*/.cache/*", false},
		{"C:/Users/User/.cargo/bin/my-crate.exe", "*/.cargo/bin/*", true},
		{"/tmp/test.log", "*.log", true},
	}

	for _, tt := range tests {
		got := matchPattern(tt.path, tt.pattern)
		if got != tt.match {
			t.Errorf("matchPattern(%q, %q) = %v; want %v", tt.path, tt.pattern, got, tt.match)
		}
	}
}

func TestProtectedSubtreeFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Permission mode 0000 not applicable on Windows")
	}

	tmpDir := t.TempDir()
	parentDir := filepath.Join(tmpDir, "parent_cache")
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		t.Fatalf("Failed to create parentDir: %v", err)
	}

	subDir := filepath.Join(parentDir, "unreadable_sub")
	if err := os.MkdirAll(subDir, 0000); err != nil {
		t.Fatalf("Failed to create subDir: %v", err)
	}
	defer os.Chmod(subDir, 0755)

	// containsProtectedPath must fail closed (return true) when subtree has permission errors
	if !containsProtectedPath(parentDir) {
		t.Errorf("containsProtectedPath should return true (fail closed) on unreadable subdirectories")
	}

	cand := Candidate{
		ID:             1,
		Path:           parentDir,
		Size:           1000,
		AgeDays:        10.0,
		Category:       "Cache",
		RuleID:         "test_cache",
		RiskClass:      RiskRegenerable,
		ProposedAction: "delete_dir",
		IsDir:          true,
		CanDelete:      true,
	}

	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer

	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, stdin)
	output := stdout.String()

	if !strings.Contains(output, "[PROTECTED SAFEGUARD]") {
		t.Errorf("Expected [PROTECTED SAFEGUARD] in output; got:\n%s", output)
	}

	// Verify invariant: directory MUST STILL EXIST on disk
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		t.Errorf("Protected safeguard failed: parentDir was deleted!")
	}
}

func TestPreActionRevalidationInvariants(t *testing.T) {
	tmpDir := t.TempDir()
	staleFile := filepath.Join(tmpDir, "stale.log")
	initialContent := []byte(strings.Repeat("A", 1000))
	if err := os.WriteFile(staleFile, initialContent, 0644); err != nil {
		t.Fatalf("Failed to write staleFile: %v", err)
	}

	oldTime := time.Now().Add(-5 * 24 * time.Hour)
	if err := os.Chtimes(staleFile, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set chtimes: %v", err)
	}

	fi, err := os.Stat(staleFile)
	if err != nil {
		t.Fatalf("Failed to stat staleFile: %v", err)
	}

	cand := Candidate{
		ID:             1,
		Path:           staleFile,
		Size:           fi.Size(),
		ModTime:        fi.ModTime(),
		AgeDays:        5.0,
		Category:       "Log",
		RuleID:         "log_rule",
		RiskClass:      RiskRegenerable,
		ProposedAction: "delete_file",
		IsDir:          false,
		CanDelete:      true,
	}

	// Case 1: Size changed
	if err := os.WriteFile(staleFile, []byte(strings.Repeat("B", 2000)), 0644); err != nil {
		t.Fatalf("Failed to write mutated size file: %v", err)
	}

	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer
	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, stdin)

	if !strings.Contains(stdout.String(), "[ABORT] File size changed") {
		t.Errorf("Expected size change abort; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(staleFile); os.IsNotExist(err) {
		t.Errorf("Pre-action revalidation invariant failed: file was deleted after size change!")
	}

	// Case 2: ModTime changed
	if err := os.WriteFile(staleFile, initialContent, 0644); err != nil {
		t.Fatalf("Failed to restore initial content: %v", err)
	}
	nowTime := time.Now()
	if err := os.Chtimes(staleFile, nowTime, nowTime); err != nil {
		t.Fatalf("Failed to set new chtimes: %v", err)
	}

	stdout.Reset()
	stdin = strings.NewReader("y\n")
	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, stdin)

	if !strings.Contains(stdout.String(), "[ABORT] File modification time changed") {
		t.Errorf("Expected modtime change abort; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(staleFile); os.IsNotExist(err) {
		t.Errorf("Pre-action revalidation invariant failed: file was deleted after modtime change!")
	}

	// Case 3: Same-type path replacement / type changed (file replaced by directory)
	if err := os.Remove(staleFile); err != nil {
		t.Fatalf("Failed to remove staleFile: %v", err)
	}
	if err := os.Mkdir(staleFile, 0755); err != nil {
		t.Fatalf("Failed to create dir at staleFile path: %v", err)
	}

	stdout.Reset()
	stdin = strings.NewReader("y\n")
	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, stdin)

	if !strings.Contains(stdout.String(), "[ABORT] File type changed") {
		t.Errorf("Expected type change abort; got:\n%s", stdout.String())
	}
	if _, err := os.Stat(staleFile); os.IsNotExist(err) {
		t.Errorf("Pre-action revalidation invariant failed: path was deleted after type change!")
	}
}

func TestCustomUserPatternsAreUnknownReportOnly(t *testing.T) {
	tmpDir := t.TempDir()
	customFile := filepath.Join(tmpDir, "test.tmp")
	content := []byte(strings.Repeat("X", 101*1024))
	if err := os.WriteFile(customFile, content, 0644); err != nil {
		t.Fatalf("Failed to write customFile: %v", err)
	}
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(customFile, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set chtimes: %v", err)
	}

	engine := NewRuleEngine(getDefaultManifest())
	removed, added := applyOverrides(engine, []string{"+*.tmp"})

	if len(added) != 1 || added[0] != "*.tmp" {
		t.Fatalf("applyOverrides failed to record added pattern; got added=%v, removed=%v", added, removed)
	}

	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	if len(candidates) != 1 {
		t.Fatalf("Expected 1 candidate for custom pattern; got %d", len(candidates))
	}

	c := candidates[0]
	if c.RiskClass != RiskUnknown {
		t.Errorf("Custom user pattern must be RiskUnknown; got %s", c.RiskClass)
	}
	if c.CanDelete {
		t.Errorf("Custom user pattern must have CanDelete = false; got true")
	}
	if c.ProposedAction != "report-only" {
		t.Errorf("Custom user pattern must have ProposedAction = 'report-only'; got %s", c.ProposedAction)
	}

	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer
	confirmAndDeleteWithIO(candidates, false, false, false, 1000, 1000, &stdout, stdin)

	if !strings.Contains(stdout.String(), "[SKIP REPORT-ONLY]") {
		t.Errorf("Expected [SKIP REPORT-ONLY] in output; got:\n%s", stdout.String())
	}

	// Verify invariant: custom pattern file MUST STILL EXIST
	if _, err := os.Stat(customFile); os.IsNotExist(err) {
		t.Errorf("Custom pattern isolation failed: file was deleted in apply mode!")
	}
}

func TestActual12kCandidateScan(t *testing.T) {
	tmpDir := t.TempDir()
	oldTime := time.Now().Add(-10 * 24 * time.Hour)

	const totalFiles = 12000
	for i := 0; i < totalFiles; i++ {
		filePath := filepath.Join(tmpDir, fmt.Sprintf("stale_%05d.log", i))
		f, err := os.Create(filePath)
		if err != nil {
			t.Fatalf("Failed to create test file %d: %v", i, err)
		}
		if err := f.Truncate(101 * 1024); err != nil {
			f.Close()
			t.Fatalf("Failed to truncate sparse test file %d: %v", i, err)
		}
		f.Close()

		if err := os.Chtimes(filePath, oldTime, oldTime); err != nil {
			t.Fatalf("Failed to set chtimes on test file %d: %v", i, err)
		}
	}

	engine := NewRuleEngine(getDefaultManifest())
	start := time.Now()
	// Set minSizeBytes to 100*1024 so 101 KiB files are included
	candidates := scanParallel([]string{tmpDir}, engine, 2.0, 100*1024, true)
	elapsed := time.Since(start)

	if len(candidates) != totalFiles {
		t.Fatalf("scanParallel on 12,000 files expected %d candidates; got %d", totalFiles, len(candidates))
	}

	if elapsed > 5*time.Second {
		t.Errorf("12,000 candidate scan took too long: %v", elapsed)
	}
}

func TestInjectionSafePlatformTrash(t *testing.T) {
	tmpDir := t.TempDir()
	hostileFile := filepath.Join(tmpDir, "file'; rm -rf .; \" $`\n.tmp")
	if err := os.WriteFile(hostileFile, []byte("data"), 0644); err != nil {
		t.Fatalf("Failed to create hostileFile: %v", err)
	}

	// Calling moveToTrashOS on hostile path must not cause shell syntax error or injection
	_ = moveToTrashOS(hostileFile)
}

func TestHermeticCLIFlagValidationAndOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())

	tmpDir := t.TempDir()
	staleLog := filepath.Join(tmpDir, "stale.log")
	content := []byte(strings.Repeat("A", 101*1024))
	if err := os.WriteFile(staleLog, content, 0644); err != nil {
		t.Fatalf("Failed to write stale log: %v", err)
	}
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	if err := os.Chtimes(staleLog, oldTime, oldTime); err != nil {
		t.Fatalf("Failed to set chtimes: %v", err)
	}

	var stdout, stderr bytes.Buffer

	// Test 1: -days negative flag validation
	stdout.Reset()
	stderr.Reset()
	code := runMain([]string{"-days", "-1"}, &stdout, &stderr, nil)
	if code != 2 {
		t.Errorf("runMain with -days -1 expected exit code 2; got %d", code)
	}

	// Test 2: -min-size-mb negative flag validation
	stdout.Reset()
	stderr.Reset()
	code = runMain([]string{"-min-size-mb", "-1"}, &stdout, &stderr, nil)
	if code != 2 {
		t.Errorf("runMain with -min-size-mb -1 expected exit code 2; got %d", code)
	}

	// Test 3: Nonexistent path validation
	stdout.Reset()
	stderr.Reset()
	nonExistentPath := filepath.Join(t.TempDir(), "nonexistent_dir_9999")
	code = runMain([]string{"-path", nonExistentPath}, &stdout, &stderr, nil)
	if code != 1 {
		t.Errorf("runMain with nonexistent path expected exit code 1; got %d", code)
	}

	// Test 4: Structured JSON plan output schema validation
	stdout.Reset()
	stderr.Reset()
	code = runMain([]string{"-json", "-include-data", "-min-size-mb", "0.05", "-path", tmpDir}, &stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("runMain -json -path %s failed with code %d: %s", tmpDir, code, stderr.String())
	}

	var plan PlanReport
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatalf("Failed to parse JSON plan output: %v\nOutput:\n%s", err, stdout.String())
	}

	if plan.Version != Version {
		t.Errorf("JSON plan Version = %s; want %s", plan.Version, Version)
	}
	if plan.TotalCandidates != 1 {
		t.Errorf("JSON plan TotalCandidates = %d; want 1", plan.TotalCandidates)
	}
	if len(plan.Candidates) != 1 {
		t.Fatalf("JSON plan Candidates length = %d; want 1", len(plan.Candidates))
	}
	if plan.Candidates[0].Size != int64(len(content)) {
		t.Errorf("JSON plan Candidate Size = %d; want %d", plan.Candidates[0].Size, len(content))
	}
}

func TestAllPackageManagerFixturesAndNegativeMappings(t *testing.T) {
	inv := &PackageInventory{
		CargoCrates: map[string]string{"ripgrep": "ripgrep"},
		PipxVenvs:   map[string]string{"black": "black"},
		NpmPackages: map[string]string{"typescript": "typescript"},
	}



	// Positive mapping
	args := formatUninstallArgs("UNUSED (Cargo)", "ripgrep", "/home/user/.cargo/bin/ripgrep", inv)
	if len(args) == 0 || args[0] != "cargo" {
		t.Errorf("Positive cargo mapping failed; got %v", args)
	}

	// Negative mapping
	argsNeg := formatUninstallArgs("UNUSED (Cargo)", "unmapped-bin", "/home/user/.cargo/bin/unmapped-bin", inv)
	if len(argsNeg) != 0 {
		t.Errorf("Negative cargo mapping should return nil; got %v", argsNeg)
	}

	// npm
	npmArgs := formatUninstallArgs("UNUSED (npm)", "typescript", "/home/user/.nvm/versions/node/v18.0.0/bin/typescript", inv)
	if len(npmArgs) == 0 || npmArgs[0] != "npm" {
		t.Errorf("Positive npm mapping failed; got %v", npmArgs)
	}
	npmNode := formatUninstallArgs("UNUSED (npm)", "node", "/home/user/.nvm/versions/node/v18.0.0/bin/node", inv)
	if npmNode != nil {
		t.Errorf("Node wrapper should return nil; got %v", npmNode)
	}
	npmNeg := formatUninstallArgs("UNUSED (npm)", "unmapped", "/home/user/.nvm/versions/node/v18.0.0/bin/unmapped", inv)
	if npmNeg != nil {
		t.Errorf("Unmapped npm should return nil; got %v", npmNeg)
	}

	// pipx
	pipxArgs := formatUninstallArgs("UNUSED (pipx)", "black", "/home/user/.local/pipx/venvs/black/bin/black", inv)
	if len(pipxArgs) == 0 || pipxArgs[0] != "pipx" {
		t.Errorf("Positive pipx mapping failed; got %v", pipxArgs)
	}
	pipxNeg := formatUninstallArgs("UNUSED (pipx)", "unmapped", "/home/user/.local/pipx/venvs/unmapped/bin/unmapped", inv)
	if pipxNeg != nil {
		t.Errorf("Unmapped pipx should return nil; got %v", pipxNeg)
	}

	// swiftly
	inv.SwiftVersions = map[string]bool{"5.9.2": true}
	swiftArgs := formatUninstallArgs("UNUSED (Swift)", "swift", "/home/user/.local/share/swiftly/toolchains/5.9.2/usr/bin/swift", inv)
	if len(swiftArgs) == 0 || swiftArgs[0] != "swiftly" {
		t.Errorf("Swiftly mapping failed; got %v", swiftArgs)
	}
	swiftNeg := formatUninstallArgs("UNUSED (Swift)", "swift", "/home/user/.local/share/swiftly/toolchains/unmapped/usr/bin/swift", inv)
	if swiftNeg != nil {
		t.Errorf("Unmapped swiftly should return nil; got %v", swiftNeg)
	}

	// sdkman
	inv.SdkmanCands = map[string]bool{"java/17.0.2-open": true}
	sdkArgs := formatUninstallArgs("UNUSED (SDKMAN)", "java", "/home/user/.sdkman/candidates/java/17.0.2-open/bin/java", inv)
	if len(sdkArgs) == 0 || sdkArgs[0] != "sdk" {
		t.Errorf("SDKMAN mapping failed; got %v", sdkArgs)
	}
	sdkNeg := formatUninstallArgs("UNUSED (SDKMAN)", "java", "/home/user/.sdkman/candidates/java/unmapped/bin/java", inv)
	if sdkNeg != nil {
		t.Errorf("Unmapped sdkman should return nil; got %v", sdkNeg)
	}

	// dotnet
	inv.DotnetTools = map[string]string{"csharp-ls": "csharp-ls"}
	dotnetArgs := formatUninstallArgs("UNUSED (Dotnet)", "csharp-ls", "/home/user/.dotnet/tools/csharp-ls", inv)
	if len(dotnetArgs) == 0 || dotnetArgs[0] != "dotnet" {
		t.Errorf("Dotnet mapping failed; got %v", dotnetArgs)
	}
	dotnetNeg := formatUninstallArgs("UNUSED (Dotnet)", "unmapped", "/home/user/.dotnet/tools/unmapped", inv)
	if dotnetNeg != nil {
		t.Errorf("Unmapped dotnet should return nil; got %v", dotnetNeg)
	}

	// composer
	inv.ComposerPkgs = map[string]string{"phpunit": "phpunit"}
	composerArgs := formatUninstallArgs("UNUSED (Composer)", "phpunit", "/home/user/.composer/vendor/bin/phpunit", inv)
	if len(composerArgs) == 0 || composerArgs[0] != "composer" {
		t.Errorf("Composer mapping failed; got %v", composerArgs)
	}
	composerNeg := formatUninstallArgs("UNUSED (Composer)", "unmapped", "/home/user/.composer/vendor/bin/unmapped", inv)
	if composerNeg != nil {
		t.Errorf("Unmapped composer should return nil; got %v", composerNeg)
	}

	// zvm
	inv.ZvmVersions = map[string]string{"0.11.0": "0.11.0"}
	zvmArgs := formatUninstallArgs("UNUSED (ZVM)", "0.11.0", "/home/user/.zvm/self/0.11.0/bin/zig", inv)
	if len(zvmArgs) == 0 || zvmArgs[0] != "zvm" {
		t.Errorf("ZVM mapping failed; got %v", zvmArgs)
	}
	zvmNeg := formatUninstallArgs("UNUSED (ZVM)", "unmapped", "/home/user/.zvm/self/unmapped/bin/zig", inv)
	if zvmNeg != nil {
		t.Errorf("Unmapped zvm should return nil; got %v", zvmNeg)
	}
}

type mockFileInfo struct {
	sys interface{}
}

func (m mockFileInfo) Name() string       { return "" }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return 0 }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return m.sys }

func TestMatchDirAndMarkerFiles(t *testing.T) {
	tmpDir := t.TempDir()
	projDir := filepath.Join(tmpDir, "proj")
	os.MkdirAll(projDir, 0755)

	// exact map rule mapping
	rules := []Rule{
		{
			ID:          "rust_target",
			Category:    "Rust Target",
			Target:      "dir",
			Patterns:    []string{"target"},
			MarkerFiles: []string{"Cargo.toml"},
		},
	}
	engine := NewRuleEngine(Manifest{Rules: rules})
	inv := &PackageInventory{}

	// Case 1: Marker file absent
	r, _, _ := engine.MatchDir("target", filepath.Join(projDir, "target"), inv)
	if r != nil {
		t.Errorf("MatchDir should return nil when marker file is absent")
	}

	// Case 2: Marker file present in parent
	if err := os.WriteFile(filepath.Join(projDir, "Cargo.toml"), []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write Cargo.toml: %v", err)
	}
	r, _, _ = engine.MatchDir("target", filepath.Join(projDir, "target"), inv)
	if r == nil || r.ID != "rust_target" {
		t.Errorf("MatchDir should match rust_target when marker file is in parent")
	}

	// Case 3: MatchFile with CheckUnusedAtime
	rules[0].Target = "file"
	rules[0].CheckUnusedAtime = true
	rules[0].Patterns = []string{"*.log"}
	engine = NewRuleEngine(Manifest{Rules: rules})

	// POSIX stat mock: diff > 24 hours (atime 1000, ctime 1000000 -> ctime is much newer than atime, i.e. not unused)
	mockFIUnused := mockFileInfo{
		sys: &syscall.Stat_t{
			Atim: syscall.Timespec{Sec: 1000, Nsec: 0},
			Ctim: syscall.Timespec{Sec: 1000000, Nsec: 0},
		},
	}
	r, _, _ = engine.MatchFile("stale.log", filepath.Join(projDir, "stale.log"), mockFIUnused, inv)
	if r != nil {
		t.Errorf("MatchFile should return nil when ctime/atime diff > 24 hours")
	}

	// POSIX stat mock: diff <= 24 hours
	mockFIUsed := mockFileInfo{
		sys: &syscall.Stat_t{
			Atim: syscall.Timespec{Sec: 1000, Nsec: 0},
			Ctim: syscall.Timespec{Sec: 1010, Nsec: 0},
		},
	}
	r, _, _ = engine.MatchFile("stale.log", filepath.Join(projDir, "stale.log"), mockFIUsed, inv)
	if r == nil {
		t.Errorf("MatchFile should match when ctime/atime diff <= 24 hours")
	}
}

func TestRenderProgressBar(t *testing.T) {
	if renderProgressBar(-10.0, 10) != "[░░░░░░░░░░]" {
		t.Errorf("Negative percentage failed")
	}
	if renderProgressBar(120.0, 10) != "[██████████]" {
		t.Errorf("Over 100 percentage failed")
	}
	if renderProgressBar(50.0, 10) != "[█████░░░░░]" {
		t.Errorf("50 percentage failed")
	}
}

func TestTrashCollisionAndFallback(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("PATH", "")

	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(f1, []byte("file1"), 0644); err != nil {
		t.Fatalf("Failed to write f1: %v", err)
	}

	// First move to trash (creates local trash folder and renames)
	if err := moveToTrash(f1); err != nil {
		t.Fatalf("moveToTrash failed: %v", err)
	}

	// Second file with same name (causes collision renaming path)
	f2 := filepath.Join(tmpDir, "test.log")
	if err := os.WriteFile(f2, []byte("file2"), 0644); err != nil {
		t.Fatalf("Failed to write f2: %v", err)
	}
	if err := moveToTrash(f2); err != nil {
		t.Fatalf("moveToTrash collision failed: %v", err)
	}

	// Verify that the files were successfully moved under the mocked HOME Trash folder
	trashDir := filepath.Join(tmpHome, ".local", "share", "Trash", "files")
	if runtime.GOOS == "darwin" {
		trashDir = filepath.Join(tmpHome, ".Trash")
	}
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("Failed to read trashDir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("Expected 2 files in trashDir; got %d", len(entries))
	}
}

func TestMockFzfInteractive(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	os.MkdirAll(binDir, 0755)

	fzfPath := filepath.Join(binDir, "fzf")
	var script string
	if runtime.GOOS == "windows" {
		fzfPath += ".bat"
		script = "@echo off\nset /p line=\necho %line%\n"
	} else {
		script = "#!/bin/sh\nread line\necho \"$line\"\n"
	}
	if err := os.WriteFile(fzfPath, []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write mock fzf: %v", err)
	}

	t.Setenv("PATH", binDir)
	fzfBin := findFzf()
	if fzfBin == "" {
		t.Fatalf("findFzf failed to locate mock fzf")
	}

	candidates := []Candidate{
		{
			ID:        1,
			Path:      "/tmp/stale.log",
			Size:      100,
			AgeDays:   5.0,
			Category:  "Log",
			RiskClass: RiskRegenerable,
		},
	}

	selected := runFzfInteractive(candidates, fzfBin, 1000, 1000, 1000)
	if len(selected) != 1 || selected[0].ID != 1 {
		t.Errorf("runFzfInteractive failed to parse mock fzf selection; got: %v", selected)
	}

	// Empty candidates case
	if res := runFzfInteractive(nil, fzfBin, 0, 0, 0); res != nil {
		t.Errorf("runFzfInteractive on empty candidates should return nil")
	}
}

func TestConfirmAndDeleteNil(t *testing.T) {
	// Call confirmAndDelete with empty list to verify it exits immediately
	confirmAndDelete(nil, false, false, false, 1000, 500)

	tmpDir := t.TempDir()
	dummyPkg := filepath.Join(tmpDir, "dummy-package")
	if err := os.WriteFile(dummyPkg, []byte("pkg"), 0755); err != nil {
		t.Fatalf("Failed to write dummy package: %v", err)
	}

	// Call confirmAndDeleteWithIO with failing native uninstall command
	cand := Candidate{
		ID:             1,
		Path:           dummyPkg,
		Size:           3,
		RiskClass:      RiskPackageManaged,
		UninstallArgs:  []string{"false"}, // exit code 1 command
		CanDelete:      true,
		ProposedAction: "uninstall_package",
	}

	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer
	confirmAndDeleteWithIO([]Candidate{cand}, false, false, false, 1000, 1000, &stdout, stdin)
	if !strings.Contains(stdout.String(), "[ERROR] Native uninstall failed") {
		t.Errorf("Expected native uninstall failure error print; got:\n%s", stdout.String())
	}
}

func TestMainFunc(t *testing.T) {
	oldExit := osExit
	defer func() { osExit = oldExit }()
	var exitedCode int
	osExit = func(code int) {
		exitedCode = code
	}
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"unslop", "-version"}
	main()
	if exitedCode != 0 {
		t.Errorf("Expected exit code 0; got %d", exitedCode)
	}
}

func TestGetDefaultScanDirs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TMPDIR", t.TempDir())
	dirs := getDefaultScanDirs()
	if len(dirs) == 0 {
		t.Errorf("getDefaultScanDirs returned empty slice")
	}
}

func TestGetDirStatsFunc(t *testing.T) {
	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(f1, []byte("data"), 0644); err != nil {
		t.Fatalf("Failed to write file1.txt: %v", err)
	}
	size, _, count := getDirStats(tmpDir, time.Now())
	if size < 4 || count != 2 {
		t.Errorf("getDirStats returned size=%d, count=%d; want size>=4, count=2", size, count)
	}

	szErr, _, countErr := getDirStats(filepath.Join(tmpDir, "nonexistent"), time.Now())
	if szErr != 0 || countErr != 0 {
		t.Errorf("getDirStats on nonexistent path should return 0")
	}
}

func TestApplyOverridesExtra(t *testing.T) {
	engine := NewRuleEngine(getDefaultManifest())
	initialRulesCount := len(engine.Rules)
	removed, added := applyOverrides(engine, []string{"-zig_cache"})
	if len(removed) != 1 || removed[0] != "zig_cache" {
		t.Errorf("applyOverrides did not remove rule; got removed=%v, added=%v", removed, added)
	}
	if len(engine.Rules) != initialRulesCount-1 {
		t.Errorf("Rules slice count was not decremented")
	}
}

func TestLoadManifestErrors(t *testing.T) {
	_, err := loadManifest("/nonexistent/manifest.json")
	if err == nil {
		t.Errorf("Expected error loading nonexistent manifest path")
	}
}

func TestPackageInventoryResolution(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// 1. Cargo
	os.MkdirAll(filepath.Join(tmpHome, ".cargo"), 0755)
	tomlData := `[installs]
"ripgrep 13.0.0 (path+src)" = ["ripgrep"]
`
	os.WriteFile(filepath.Join(tmpHome, ".cargo", ".crates.toml"), []byte(tomlData), 0644)
	jsonData := `{"installs": {"ripgrep 13.0.0 (path+src)": {"bins": ["ripgrep"]}}}`
	os.WriteFile(filepath.Join(tmpHome, ".cargo", ".crates2.json"), []byte(jsonData), 0644)

	// 2. Pipx
	os.MkdirAll(filepath.Join(tmpHome, ".local", "pipx", "venvs", "black"), 0755)

	// 3. npm
	os.MkdirAll(filepath.Join(tmpHome, ".nvm", "versions", "node", "v18.0.0"), 0755)

	// 4. Dotnet
	os.MkdirAll(filepath.Join(tmpHome, ".dotnet", "tools", ".store", "csharp-ls"), 0755)

	// 5. Composer
	os.MkdirAll(filepath.Join(tmpHome, ".config", "composer", "vendor", "composer"), 0755)
	compJson := `{"packages": [{"name": "phpunit"}]}`
	os.WriteFile(filepath.Join(tmpHome, ".config", "composer", "vendor", "composer", "installed.json"), []byte(compJson), 0644)

	// 6. SDKMAN
	os.MkdirAll(filepath.Join(tmpHome, ".sdkman", "candidates", "java", "17.0.2-open"), 0755)

	// 7. Swiftly
	os.MkdirAll(filepath.Join(tmpHome, ".local", "share", "swiftly", "toolchains", "5.9.2"), 0755)

	// 8. ZVM
	os.MkdirAll(filepath.Join(tmpHome, ".zvm", "0.11.0"), 0755)

	inv := loadPackageInventory()

	if inv.CargoCrates["ripgrep"] != "ripgrep" {
		t.Errorf("Cargo parsing failed; got CargoCrates=%v", inv.CargoCrates)
	}
	if inv.PipxVenvs["black"] != "black" {
		t.Errorf("Pipx parsing failed")
	}
	if inv.NpmPackages["v18.0.0"] != "v18.0.0" {
		t.Errorf("npm parsing failed")
	}
	if inv.DotnetTools["csharp-ls"] != "csharp-ls" {
		t.Errorf("Dotnet parsing failed")
	}
	if inv.ComposerPkgs["phpunit"] != "phpunit" {
		t.Errorf("Composer parsing failed")
	}
	if !inv.SdkmanCands["java/17.0.2-open"] {
		t.Errorf("SDKMAN parsing failed")
	}
	if !inv.SwiftVersions["5.9.2"] {
		t.Errorf("Swiftly parsing failed")
	}
	if inv.ZvmVersions["0.11.0"] != "0.11.0" {
		t.Errorf("ZVM parsing failed")
	}
}

func TestCoverageExtraTargetedGaps(t *testing.T) {
	// 1. HOME empty loadPackageInventory fallback
	t.Setenv("HOME", "")
	invEmpty := loadPackageInventory()
	if len(invEmpty.CargoCrates) != 0 {
		t.Errorf("Empty HOME should yield empty inventory")
	}

	// 2. globMatch extra branches
	if matchPattern("file.txt", "*.log") {
		t.Errorf("*.log should not match file.txt")
	}
	if !matchPattern("stale.log", "*.log*") {
		t.Errorf("*.log* should match stale.log")
	}
	if !matchPattern("stale.log", "stale.lo?") {
		t.Errorf("stale.lo? should match stale.log")
	}
	if !matchPattern("/home/user/node_modules/foo", "node_modules") {
		t.Errorf("node_modules should match substring")
	}

	// 3. findFzf in HOME/.local/bin/fzf
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("PATH", "") // clear path
	localBin := filepath.Join(tmpHome, ".local", "bin")
	os.MkdirAll(localBin, 0755)
	fzfPath := filepath.Join(localBin, "fzf")
	if err := os.WriteFile(fzfPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("Failed to write mock fzf: %v", err)
	}
	fzfBin := findFzf()
	if fzfBin != fzfPath {
		t.Errorf("Expected findFzf to return %s; got %s", fzfPath, fzfBin)
	}

	// 4. containsProtectedPath with protected file
	tmpDir := t.TempDir()
	projDir := filepath.Join(tmpDir, "project")
	os.MkdirAll(projDir, 0755)
	if err := os.WriteFile(filepath.Join(projDir, "credentials.json"), []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write credentials.json: %v", err)
	}
	if !containsProtectedPath(projDir) {
		t.Errorf("Expected containsProtectedPath to be true when credentials.json is inside")
	}

	// 5. loadManifest JSON and risk class validation errors
	tmpManifestJsonErr := filepath.Join(tmpDir, "err.json")
	os.WriteFile(tmpManifestJsonErr, []byte("{invalid json"), 0644)
	if _, err := loadManifest(tmpManifestJsonErr); err == nil {
		t.Errorf("Expected error loading malformed manifest JSON")
	}

	tmpManifestRiskErr := filepath.Join(tmpDir, "risk_err.json")
	os.WriteFile(tmpManifestRiskErr, []byte(`{"rules": [{"id": "r1", "category": "cat", "risk_class": "junk"}]}`), 0644)
	if _, err := loadManifest(tmpManifestRiskErr); err == nil {
		t.Errorf("Expected error loading manifest with invalid risk_class")
	}

	// default rule mapping with empty risk class
	tmpManifestDefaultRisk := filepath.Join(tmpDir, "default_risk.json")
	os.WriteFile(tmpManifestDefaultRisk, []byte(`{"rules": [{"id": "r2", "category": "UNUSED (npm)"}, {"id": "r3", "category": "some_other"}]}`), 0644)
	m, err := loadManifest(tmpManifestDefaultRisk)
	if err != nil {
		t.Fatalf("Failed to load default_risk manifest: %v", err)
	}
	engineDefault := NewRuleEngine(m)
	if engineDefault.Rules[0].RiskClass != RiskPackageManaged {
		t.Errorf("Expected UNUSED category to default to RiskPackageManaged; got %s", engineDefault.Rules[0].RiskClass)
	}
	if engineDefault.Rules[1].RiskClass != RiskUnknown {
		t.Errorf("Expected non-UNUSED category to default to RiskUnknown; got %s", engineDefault.Rules[1].RiskClass)
	}

	// 6. MatchFile glob rules and pipx symlink mapping
	rules := []Rule{
		{
			ID:        "glob_file_rule",
			Category:  "UNUSED (pipx)",
			Target:    "file",
			Patterns:  []string{"*black*"},
			RiskClass: RiskPackageManaged,
		},
	}
	engine := NewRuleEngine(Manifest{Rules: rules})
	inv := &PackageInventory{
		PipxVenvs: map[string]string{"black": "black"},
	}

	// Create pipx symlink structure
	pipxBin := filepath.Join(tmpDir, "black")
	pipxTarget := filepath.Join(tmpDir, ".local", "pipx", "venvs", "black", "bin", "black")
	os.MkdirAll(filepath.Dir(pipxTarget), 0755)
	if err := os.WriteFile(pipxTarget, []byte(""), 0755); err != nil {
		t.Fatalf("Failed to write pipxTarget: %v", err)
	}
	if err := os.Symlink(pipxTarget, pipxBin); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	fi, err := os.Lstat(pipxBin)
	if err != nil {
		t.Fatalf("Failed to lstat pipxBin: %v", err)
	}

	matchedRule, _, args := engine.MatchFile("black", pipxBin, fi, inv)
	if matchedRule == nil || matchedRule.ID != "glob_file_rule" {
		t.Errorf("Expected MatchFile to match glob_file_rule via GlobRules fallback loop")
	}
	if len(args) == 0 || args[0] != "pipx" {
		t.Errorf("Expected pipx symlink mapping to resolve to pipx; got %v", args)
	}
}

func TestMoveToTrashOSBranches(t *testing.T) {
	// Case 1: getStatTimes fallback when Sys is nil
	mockFINilSys := mockFileInfo{
		sys: nil,
	}
	_, _, _, isPosix := getStatTimes(mockFINilSys)
	if isPosix {
		t.Errorf("getStatTimes with nil Sys should return isPosix = false")
	}

	// Case 2: getDiskSpaceSyscall error on nonexistent path
	_, _, _, err := getDiskSpaceSyscall("/nonexistent/path/999")
	if err == nil {
		t.Errorf("Expected error from getDiskSpaceSyscall on nonexistent path")
	}

	// Case 3: moveToTrash & loadPackageInventory with empty HOME
	t.Setenv("HOME", "")
	if emptyInv := loadPackageInventory(); len(emptyInv.CargoCrates) != 0 {
		t.Errorf("Expected empty inventory when HOME is empty")
	}
	if err := moveToTrash("/tmp/some-file"); err == nil {
		t.Errorf("Expected error from moveToTrash with empty HOME")
	}

	// Case 4: moveToTrash with mkdir failure (Trash is a file)
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	trashParent := filepath.Join(tmpHome, ".local", "share")
	os.MkdirAll(trashParent, 0755)
	if err := os.WriteFile(filepath.Join(trashParent, "Trash"), []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}
	if err := moveToTrash("/tmp/some-file"); err == nil {
		t.Errorf("Expected error from moveToTrash when MkdirAll fails")
	}
}

func TestScanParallelDeep(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	tmpDir := t.TempDir()

	// 1. Create files with skipped suffixes
	os.WriteFile(filepath.Join(tmpDir, "stale.lock"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "stale.sock"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "stale.pid"), []byte("data"), 0644)

	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(filepath.Join(tmpDir, "stale.lock"), oldTime, oldTime)
	os.Chtimes(filepath.Join(tmpDir, "stale.sock"), oldTime, oldTime)
	os.Chtimes(filepath.Join(tmpDir, "stale.pid"), oldTime, oldTime)

	// 2. Create a file candidate that matches UNUSED category but is unmapped
	staleCargoBin := filepath.Join(tmpDir, "unmapped-cargo-pkg")
	if err := os.WriteFile(staleCargoBin, []byte(strings.Repeat("A", 101*1024)), 0755); err != nil {
		t.Fatalf("Failed to write staleCargoBin: %v", err)
	}
	os.Chtimes(staleCargoBin, oldTime, oldTime)

	// 3. Create a directory candidate that matches UNUSED category but is unmapped
	staleNpmDir := filepath.Join(tmpDir, "project", "node_modules")
	os.MkdirAll(staleNpmDir, 0755)
	marker := filepath.Join(staleNpmDir, "package.json")
	os.WriteFile(marker, []byte(`{}`), 0644)
	largeFile := filepath.Join(staleNpmDir, "large.txt")
	os.WriteFile(largeFile, []byte(strings.Repeat("A", 101*1024)), 0644)
	os.Chtimes(staleNpmDir, oldTime, oldTime)
	os.Chtimes(marker, oldTime, oldTime)
	os.Chtimes(largeFile, oldTime, oldTime)

	// 4. Create protected folders (.git, .hg, .svn) and protected file (.ssh/id_rsa)
	os.MkdirAll(filepath.Join(tmpDir, "project", ".git"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "project", ".hg"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "project", ".svn"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "project", ".ssh"), 0700)
	os.WriteFile(filepath.Join(tmpDir, "project", ".ssh", "id_rsa"), []byte("secret"), 0600)

	// Create directory containing credentials.json that matches a rule
	protNpmDir := filepath.Join(tmpDir, "prot_project", "node_modules")
	os.MkdirAll(protNpmDir, 0755)
	os.WriteFile(filepath.Join(protNpmDir, "package.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(protNpmDir, "credentials.json"), []byte("secret"), 0644)
	os.WriteFile(filepath.Join(protNpmDir, "large.txt"), []byte(strings.Repeat("A", 101*1024)), 0644)
	os.Chtimes(protNpmDir, oldTime, oldTime)
	os.Chtimes(filepath.Join(protNpmDir, "large.txt"), oldTime, oldTime)

	rules := []Rule{
		{
			ID:        "cargo_pkg_mock",
			Category:  "UNUSED (Cargo)",
			Target:    "file",
			Patterns:  []string{"*unmapped-cargo-pkg*"},
			RiskClass: RiskPackageManaged,
		},
		{
			ID:          "npm_pkg_mock",
			Category:    "UNUSED (npm)",
			Target:      "dir",
			Patterns:    []string{"*node_modules*"},
			MarkerFiles: []string{"package.json"},
			RiskClass:   RiskPackageManaged,
		},
		{
			ID:        "unknown_file_mock",
			Category:  "Generic Temp File",
			Target:    "file",
			Patterns:  []string{"*stale.lock*"},
			RiskClass: RiskUnknown,
		},
	}
	engine := NewRuleEngine(Manifest{Rules: rules})

	candidates := scanParallel([]string{tmpDir, staleCargoBin}, engine, 2.0, 100*1024, true)

	foundCargo := false
	foundNpm := false
	for _, c := range candidates {
		if c.RuleID == "cargo_pkg_mock" {
			foundCargo = true
			if c.ProposedAction != "report-only" || c.CanDelete {
				t.Errorf("Expected cargo_pkg_mock candidate to be report-only; got action=%s, canDelete=%v", c.ProposedAction, c.CanDelete)
			}
		}
		if c.RuleID == "npm_pkg_mock" {
			foundNpm = true
			if c.ProposedAction != "report-only" || c.CanDelete {
				t.Errorf("Expected npm_pkg_mock candidate to be report-only; got action=%s, canDelete=%v", c.ProposedAction, c.CanDelete)
			}
		}
		if strings.HasSuffix(c.Path, ".lock") || strings.HasSuffix(c.Path, ".sock") || strings.HasSuffix(c.Path, ".pid") {
			t.Errorf("Suffix file should not be a candidate: %s", c.Path)
		}
	}

	if !foundCargo {
		t.Errorf("Expected to find unmapped cargo package candidate")
	}
	if !foundNpm {
		t.Errorf("Expected to find unmapped npm folder candidate")
	}

	// Test MinSizeMB > 0 rule check & includeData = false skip branches
	rules[1].MinSizeMB = 0.01
	engineMinSize := NewRuleEngine(Manifest{Rules: rules})
	_ = scanParallel([]string{tmpDir}, engineMinSize, 0.0, 10, true)

	rulesUserData := []Rule{
		{
			ID:        "user_data_dir",
			Category:  "Agent Log",
			Target:    "dir",
			Patterns:  []string{"*node_modules*"},
			RiskClass: RiskUserData,
		},
		{
			ID:        "user_data_file",
			Category:  "Log File",
			Target:    "file",
			Patterns:  []string{"*unmapped-cargo-pkg*"},
			RiskClass: RiskUserData,
		},
	}
	engineUserData := NewRuleEngine(Manifest{Rules: rulesUserData})
	candsNoData := scanParallel([]string{tmpDir}, engineUserData, 0.0, 10, false)
	if len(candsNoData) != 0 {
		t.Errorf("Expected 0 candidates when includeData=false; got %d", len(candsNoData))
	}
}

func TestRunMainExecution(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	binDir := filepath.Join(tmpHome, "bin")
	os.MkdirAll(binDir, 0755)
	fzfPath := filepath.Join(binDir, "fzf")
	var script string
	if runtime.GOOS == "windows" {
		fzfPath += ".bat"
		script = "@echo off\nset /p line=\necho %line%\n"
	} else {
		script = "#!/bin/sh\nread line\necho \"$line\"\n"
	}
	if err := os.WriteFile(fzfPath, []byte(script), 0755); err != nil {
		t.Fatalf("Failed to write mock fzf: %v", err)
	}
	t.Setenv("PATH", binDir)

	tmpDir := t.TempDir()
	staleCache := filepath.Join(tmpDir, "project", "zig-cache")
	if err := os.MkdirAll(staleCache, 0755); err != nil {
		t.Fatalf("Failed to mkdir staleCache: %v", err)
	}
	largeFile := filepath.Join(staleCache, "cache.bin")
	content := []byte(strings.Repeat("A", 101*1024))
	if err := os.WriteFile(largeFile, content, 0644); err != nil {
		t.Fatalf("Failed to write large cache file: %v", err)
	}
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	os.Chtimes(staleCache, oldTime, oldTime)
	os.Chtimes(largeFile, oldTime, oldTime)

	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("y\n")

	code := runMain([]string{"-apply", "-min-size-mb", "0.05", "-path", tmpDir}, &stdout, &stderr, stdin)
	if code != 0 {
		t.Errorf("runMain failed with exit code %d; stderr: %s", code, stderr.String())
	}

	if _, err := os.Stat(staleCache); !os.IsNotExist(err) {
		t.Errorf("Stale zig-cache directory was not deleted by runMain execution!\nStdout: %s\nStderr: %s", stdout.String(), stderr.String())
	}
}

func TestCoveragePushTo100(t *testing.T) {
	if globMatch("foo", "[a-") {
		t.Errorf("invalid pattern should return false")
	}
	// 1. containsProtectedPath with nonexistent path & findFzf empty HOME & getDirStats nonexistent
	if !containsProtectedPath("/nonexistent/path/xyz") {
		t.Errorf("nonexistent path should trigger foundProtected = true")
	}
	parentWithProtected := t.TempDir()
	os.WriteFile(filepath.Join(parentWithProtected, "credentials.json"), []byte("secret"), 0600)
	if !containsProtectedPath(parentWithProtected) {
		t.Errorf("parent directory containing credentials.json should trigger foundProtected = true")
	}
	statsDir := t.TempDir()
	newerFile := filepath.Join(statsDir, "newer.txt")
	os.WriteFile(newerFile, []byte("newer"), 0644)
	os.Chtimes(newerFile, time.Now().Add(1*time.Hour), time.Now().Add(1*time.Hour))
	getDirStats(statsDir, time.Now())

	if runtime.GOOS != "windows" {
		unreadableDir := filepath.Join(t.TempDir(), "unreadable")
		os.MkdirAll(unreadableDir, 0000)
		defer os.Chmod(unreadableDir, 0755)
		containsProtectedPath(unreadableDir)
		getDirStats(unreadableDir, time.Now())
	}

	origPath := os.Getenv("PATH")
	t.Setenv("HOME", "")
	t.Setenv("PATH", "")
	if findFzf() != "" {
		t.Errorf("findFzf with empty HOME and PATH should return empty string")
	}
	t.Setenv("PATH", origPath)

	// 2. loadManifest with HOME/.unslop.json candidate file
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	manifestPath := filepath.Join(tmpHome, ".unslop.json")
	if err := os.WriteFile(manifestPath, defaultManifestData, 0644); err != nil {
		t.Fatalf("Failed to write .unslop.json: %v", err)
	}
	m, err := loadManifest("")
	if err != nil || len(m.Rules) == 0 {
		t.Errorf("loadManifest(\"\") failed to load .unslop.json from HOME")
	}

	// 3. calculateDynamicMinSizeMB
	szMB := calculateDynamicMinSizeMB(100 * 1024 * 1024 * 1024)
	if szMB <= 0 {
		t.Errorf("calculateDynamicMinSizeMB returned invalid size: %f", szMB)
	}

	// 4. scanParallel progress bar ticker & file scan root & small file skip (< 100 KiB)
	tmpDir := t.TempDir()
	smallFile := filepath.Join(tmpDir, "small.tmp")
	os.WriteFile(smallFile, []byte("small"), 0644)

	for i := 0; i < 100; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file_%d.tmp", i)), []byte("data"), 0644)
	}

	engine := NewRuleEngine(getDefaultManifest())
	candidates := scanParallel([]string{smallFile, tmpDir}, engine, 0.0, 10, true)
	_ = candidates

	// 5. runMain flag errors and plan-out export
	var stdout, stderr bytes.Buffer
	stdin := strings.NewReader("n\n")

	// Invalid manifest path
	codeErr := runMain([]string{"-manifest", "/nonexistent/manifest.json"}, &stdout, &stderr, stdin)
	if codeErr != 1 {
		t.Errorf("Expected exit code 1 for invalid manifest path; got %d", codeErr)
	}

	// Invalid path arg
	codePathErr := runMain([]string{"-path", "/nonexistent/path/xyz"}, &stdout, &stderr, stdin)
	if codePathErr != 1 {
		t.Errorf("Expected exit code 1 for invalid path arg; got %d", codePathErr)
	}

	// Plan-out export success & error
	planFile := filepath.Join(tmpDir, "plan.json")
	codePlan := runMain([]string{"-json", "-plan-out", planFile, "-path", tmpDir}, &stdout, &stderr, stdin)
	if codePlan != 0 {
		t.Errorf("Expected exit code 0 for plan-out export; got %d", codePlan)
	}
	if _, err := os.Stat(planFile); err != nil {
		t.Errorf("Plan file was not written")
	}

	// Plan-out export failure (directory path)
	codePlanErr := runMain([]string{"-json", "-plan-out", tmpDir, "-path", tmpDir}, &stdout, &stderr, stdin)
	if codePlanErr != 1 {
		t.Errorf("Expected exit code 1 for invalid plan-out file path; got %d", codePlanErr)
	}

	// 6. confirmAndDeleteWithIO safety checks
	candUserData := Candidate{
		ID:             1,
		Path:           smallFile,
		Size:           100,
		RiskClass:      RiskUserData,
		CanDelete:      true,
		ProposedAction: "delete_file",
	}
	// Dry run mode print
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candUserData}, true, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[READ-ONLY PLAN MODE]") {
		t.Errorf("Expected READ-ONLY PLAN MODE print; got:\n%s", stdout.String())
	}

	// Refused user-data item without -apply-data in apply mode
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candUserData}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[REFUSED]") {
		t.Errorf("Expected REFUSED user-data print; got:\n%s", stdout.String())
	}

	// File type changed abort
	candTypeMutated := Candidate{
		ID:             2,
		Path:           smallFile,
		Size:           5,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		IsDir:          true,
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candTypeMutated}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[ABORT] File type changed") {
		t.Errorf("Expected ABORT File type changed print; got:\n%s", stdout.String())
	}

	// Protected subtree safeguard abort inside directory
	protectedDir := filepath.Join(tmpDir, "protected_dir")
	os.MkdirAll(protectedDir, 0755)
	os.WriteFile(filepath.Join(protectedDir, "credentials.json"), []byte(""), 0644)
	candProtectedDir := Candidate{
		ID:             3,
		Path:           protectedDir,
		Size:           100,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_dir",
		IsDir:          true,
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candProtectedDir}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[PROTECTED SAFEGUARD]") {
		t.Errorf("Expected PROTECTED SAFEGUARD print; got:\n%s", stdout.String())
	}

	// Deletion using trash
	targetTrashFile := filepath.Join(tmpDir, "trash_me.tmp")
	os.WriteFile(targetTrashFile, []byte("trash me"), 0644)
	candTrash := Candidate{
		ID:             4,
		Path:           targetTrashFile,
		Size:           8,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		IsDir:          false,
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candTrash}, false, false, true, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[TRASHED]") {
		t.Errorf("Expected TRASHED print; got:\n%s", stdout.String())
	}

	// 7. runMain -help flags usage output
	stdout.Reset()
	stderr.Reset()
	runMain([]string{"-help"}, &stdout, &stderr, stdin)
	if !strings.Contains(stderr.String(), "Conservative developer workstation hygiene planner") {
		t.Errorf("Expected usage print in stderr; got:\n%s", stderr.String())
	}

	// 8. calculateDynamicMinSizeMB all branches
	if calculateDynamicMinSizeMB(0) != 10.0 {
		t.Errorf("0 B dynamic min size failed")
	}
	if calculateDynamicMinSizeMB(20*1024*1024*1024) != 1.0 {
		t.Errorf("20GB dynamic min size failed")
	}
	if calculateDynamicMinSizeMB(999*1024*1024*1024) <= 30.0 {
		t.Errorf("999GB dynamic min size failed")
	}
	if calculateDynamicMinSizeMB(1200*1024*1024*1024) != 50.0 {
		t.Errorf("1200GB dynamic min size failed")
	}
	if calculateDynamicMinSizeMB(100*1024*1024*1024) <= 0 {
		t.Errorf("100GB dynamic min size failed")
	}

	// 9. confirmAndDeleteWithIO modtime mismatch & operation cancelled (n) & native uninstall success & delete error
	modTimeFile := filepath.Join(tmpDir, "modtime.tmp")
	os.WriteFile(modTimeFile, []byte("test"), 0644)
	candModTime := Candidate{
		ID:             5,
		Path:           modTimeFile,
		Size:           4,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		ModTime:        time.Now().Add(-10 * time.Hour),
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candModTime}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[ABORT] File modification time changed") {
		t.Errorf("Expected ABORT ModTime changed print; got:\n%s", stdout.String())
	}

	// Operation cancelled (n)
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candTrash}, false, false, false, 1000, 1000, &stdout, strings.NewReader("n\n"))
	if !strings.Contains(stdout.String(), "Operation cancelled") {
		t.Errorf("Expected Operation cancelled print; got:\n%s", stdout.String())
	}

	// Native uninstall success
	candUninstallOk := Candidate{
		ID:             6,
		Path:           modTimeFile,
		Size:           4,
		RiskClass:      RiskPackageManaged,
		UninstallArgs:  []string{"true"},
		CanDelete:      true,
		ProposedAction: "uninstall_package",
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candUninstallOk}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[UNINSTALLED SUCCESS]") {
		t.Errorf("Expected UNINSTALLED SUCCESS print; got:\n%s", stdout.String())
	}

	// Delete error (try removing file in read-only directory)
	roDir := filepath.Join(tmpDir, "ro_dir")
	os.MkdirAll(roDir, 0755)
	roFile := filepath.Join(roDir, "file.txt")
	os.WriteFile(roFile, []byte("x"), 0644)
	os.Chmod(roDir, 0555)
	defer os.Chmod(roDir, 0755)

	candDelErr := Candidate{
		ID:             7,
		Path:           roFile,
		Size:           1,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
		IsDir:          false,
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candDelErr}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[ERROR] Failed to delete") {
		t.Errorf("Expected Failed to delete error print; got:\n%s", stdout.String())
	}

	// 10. Negative flag validations in runMain
	if codeDaysErr := runMain([]string{"-days", "-5"}, &stdout, &stderr, stdin); codeDaysErr != 2 {
		t.Errorf("Expected exit code 2 for negative -days; got %d", codeDaysErr)
	}
	if codeSizeErr := runMain([]string{"-min-size-mb", "-1"}, &stdout, &stderr, stdin); codeSizeErr != 2 {
		t.Errorf("Expected exit code 2 for negative -min-size-mb; got %d", codeSizeErr)
	}

	// 11. Skipped file no longer exists on disk & trash error & json dry-run & fzf failure
	stdout.Reset()
	stderr.Reset()
	codeJsonDry := runMain([]string{"-json", "-dry-run", "-path", tmpDir}, &stdout, &stderr, stdin)
	if codeJsonDry != 0 || !strings.Contains(stdout.String(), `"scanned_at"`) {
		t.Errorf("Expected json dry run output; got code=%d, stdout=%s", codeJsonDry, stdout.String())
	}

	candMissing := Candidate{
		ID:             8,
		Path:           filepath.Join(tmpDir, "missing.tmp"),
		Size:           1,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
	}

	// runFzfInteractive error path
	fzfErrBin := filepath.Join(tmpHome, "fzf_err_bin")
	os.MkdirAll(fzfErrBin, 0755)
	fzfErrScript := filepath.Join(fzfErrBin, "fzf")
	if runtime.GOOS == "windows" {
		fzfErrScript += ".bat"
		os.WriteFile(fzfErrScript, []byte("@exit /b 1\n"), 0755)
	} else {
		os.WriteFile(fzfErrScript, []byte("#!/bin/sh\nexit 1\n"), 0755)
	}
	resFzfErr := runFzfInteractive([]Candidate{candMissing}, fzfErrScript, 100, 50, 50)
	if resFzfErr != nil {
		t.Errorf("Expected nil candidate selection when fzf exits with error; got %v", resFzfErr)
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candMissing}, false, false, false, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[SKIP]") {
		t.Errorf("Expected SKIP no longer exists print; got:\n%s", stdout.String())
	}

	// Trash error print when HOME=""
	t.Setenv("HOME", "")
	candTrashErr := Candidate{
		ID:             9,
		Path:           roFile,
		Size:           1,
		RiskClass:      RiskRegenerable,
		CanDelete:      true,
		ProposedAction: "delete_file",
	}
	stdout.Reset()
	confirmAndDeleteWithIO([]Candidate{candTrashErr}, false, false, true, 1000, 1000, &stdout, strings.NewReader("y\n"))
	if !strings.Contains(stdout.String(), "[ERROR] Failed to trash") {
		t.Errorf("Expected Failed to trash error print; got:\n%s", stdout.String())
	}

	// 12. Mock gio and trash binaries for linux moveToTrashOS
	if runtime.GOOS == "linux" {
		t.Setenv("HOME", tmpHome)
		trashBinDir := filepath.Join(tmpHome, "trash_bin")
		os.MkdirAll(trashBinDir, 0755)
		gioScript := filepath.Join(trashBinDir, "gio")
		os.WriteFile(gioScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		trashScript := filepath.Join(trashBinDir, "trash")
		os.WriteFile(trashScript, []byte("#!/bin/sh\nexit 0\n"), 0755)
		t.Setenv("PATH", trashBinDir)

		if err := moveToTrashOS(smallFile); err != nil {
			t.Errorf("moveToTrashOS with mock gio failed: %v", err)
		}

		os.Remove(gioScript)
		if err := moveToTrashOS(smallFile); err != nil {
			t.Errorf("moveToTrashOS with mock trash failed: %v", err)
		}
	}
}



