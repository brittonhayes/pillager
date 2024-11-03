package main

import (
	"fmt"
	"runtime"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/scanner"
)

func main() {
	// Set scanner options
	opts := pillager.Options{
		Path:     ".",
		Workers:  runtime.NumCPU(),
		Reporter: "json",
		Redact:   true,
	}

	// Create a new gitleaks scanner
	s, _ := scanner.NewGitleaksScanner(opts)

	// Scan the current directory
	results, _ := s.Scan(opts.Path)

	// Report results
	fmt.Println(results)
}
