//go:build ignore

package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/yahn/unslop/internal/ui"
)

func sanitizeWithMap(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

func progressWithRepeat(percentage float64, width int) string {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}
	if width <= 0 {
		return "[]"
	}
	filled := int(percentage / 100 * float64(width))
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func main() {
	declarations := map[string]map[string]int{}
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(os.Args[1], directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, path, nil, 0)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(os.Args[1], path)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				add := func(name string, node ast.Node) {
					start, end := positions.Position(node.Pos()).Line, positions.Position(node.End()).Line
					declarations[relative+":"+name] = map[string]int{"start": start, "end": end, "lines": end - start + 1}
				}
				switch node := declaration.(type) {
				case *ast.FuncDecl:
					add(node.Name.Name, node)
				case *ast.GenDecl:
					for _, specification := range node.Specs {
						if node, ok := specification.(*ast.TypeSpec); ok {
							add(node.Name.Name, node)
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			panic(err)
		}
	}
	draftPositions := token.NewFileSet()
	drafts, err := parser.ParseFile(draftPositions, filepath.Join(os.Args[1], "metrics/src/architecture_probe.go"), nil, 0)
	if err != nil {
		panic(err)
	}
	draftSpans := map[string]map[string]int{}
	for _, declaration := range drafts.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && (function.Name.Name == "sanitizeWithMap" || function.Name.Name == "progressWithRepeat") {
			start, end := draftPositions.Position(function.Pos()).Line, draftPositions.Position(function.End()).Line
			draftSpans[function.Name.Name] = map[string]int{"start": start, "end": end, "lines": end - start + 1}
		}
	}
	sanitizerCases, sanitizerMismatch := 0, 0
	check := func(input string) {
		sanitizerCases++
		actual := sanitizeWithMap(input)
		if actual != ui.SanitizeTerminalString(input) {
			sanitizerMismatch++
		}
	}
	for left := 0; left < 256; left++ {
		check(string([]byte{byte(left)}))
		for right := 0; right < 256; right++ {
			check(string([]byte{byte(left), byte(right)}))
		}
	}
	for _, input := range []string{"", "hello", "界\x1b[31m", "\ufffd", "\xf0\x9f\x90\x88", "a\xffz", "\xed\xa0\x80", "\xf0\x80\x80\x80"} {
		check(input)
	}
	progressCases, progressMismatch := 0, 0
	for width := -3; width <= 20; width++ {
		for quarter := -40; quarter <= 440; quarter++ {
			actual := progressWithRepeat(float64(quarter)/4, width)
			progressCases++
			if actual != ui.RenderProgressBar(float64(quarter)/4, width) {
				progressMismatch++
			}
		}
	}
	result := map[string]any{"declarations": declarations, "draft_spans": draftSpans, "stdlib_probes": map[string]any{
		"sanitizer": map[string]int{"cases": sanitizerCases, "mismatches": sanitizerMismatch},
		"progress":  map[string]any{"cases": progressCases, "mismatches": progressMismatch, "domain": "finite percentages; widths -3 through 20; not an exhaustive equivalence proof"},
	}}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
}
