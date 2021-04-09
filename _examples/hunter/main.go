package main

import (
	"runtime"

	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/brittonhayes/pillager/pkg/rules"
	"github.com/spf13/afero"
)

func main() {
	// Create a new hunter config
	c := hunter.NewConfig(afero.NewOsFs(), ".", true, rules.Load(""), hunter.StringToFormat("JSON"), "", runtime.NumCPU())

	// Create a new hunter from the config
	h := hunter.NewHunter(c)

	// Start hunting
	_ = h.Hunt()
}
