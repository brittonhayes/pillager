// Package main is the primary entrypoint to the CLI
package main

//go:generate gomarkdoc ./pkg/...
import "github.com/brittonhayes/pillager/cmd"

func main() {
	cmd.Execute()
}
