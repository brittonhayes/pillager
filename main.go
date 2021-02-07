package main

//go:generate golangci-lint run ./...
//go:generate golines ./ -w -m 150
//go:generate gomarkdoc ./hunter/...
//go:generate gomarkdoc ./rules/...

import "github.com/brittonhayes/pillager/cmd"

func main() {
	cmd.Execute()
}
