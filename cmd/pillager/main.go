// Package pillager is the entrypoint to the Pillager CLI
package main

import (
	pillager "github.com/brittonhayes/pillager/internal/commands"
)

func main() {
	pillager.Execute()
}
