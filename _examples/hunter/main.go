package main

import (
	"github.com/brittonhayes/pillager/hunter"
	"github.com/brittonhayes/pillager/rules"
	"github.com/spf13/afero"
)

func main() {
	// Create a new hunter config
	c := hunter.NewConfig(afero.NewOsFs(), ".", true, rules.Load(""), hunter.StringToFormat("JSON"))

	// Create a new hunter from the config
	h := hunter.NewHunter(c)

	// Start hunting
	_ = h.Hunt()
}
