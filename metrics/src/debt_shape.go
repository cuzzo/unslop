//go:build ignore

package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type shape struct {
	Lines     int `json:"lines"`
	Functions int `json:"functions"`
	Decisions int `json:"decision_sites"`
	Tokens    int `json:"tokens"`
	Nodes     int `json:"ast_nodes"`
}

func main() {
	files := map[string]shape{}
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(os.Args[1], directory), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
			if err != nil {
				return err
			}
			count := shape{Lines: len(strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"))}
			var lexer scanner.Scanner
			lexer.Init(token.NewFileSet().AddFile(path, -1, len(data)), data, nil, 0)
			for {
				_, kind, _ := lexer.Scan()
				if kind == token.EOF {
					break
				}
				count.Tokens++
			}
			ast.Inspect(file, func(node ast.Node) bool {
				if node != nil {
					count.Nodes++
				}
				switch node.(type) {
				case *ast.FuncDecl:
					count.Functions++
				case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
					count.Decisions++
				}
				return true
			})
			relative, err := filepath.Rel(os.Args[1], path)
			if err != nil {
				return err
			}
			files[relative] = count
			return nil
		})
		if err != nil {
			panic(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(files); err != nil {
		panic(err)
	}
}
