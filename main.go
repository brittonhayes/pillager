//go:generate gomarkdoc ./pkg/...
// Package main is the primary entrypoint to the CLI
package main

import "github.com/brittonhayes/pillager/cmd"

func main() {
	cmd.Execute()
}
