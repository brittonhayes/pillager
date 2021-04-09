package main

import (
	"github.com/brittonhayes/pillager/cmd/pillager"
)

//go:generate golangci-lint run ./...
//go:generate gomarkdoc ./hunter/...
//go:generate gomarkdoc ./rules/...

func main() {
	pillager.Execute()
}
