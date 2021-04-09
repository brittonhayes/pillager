package main

import (
	hunter2 "github.com/brittonhayes/pillager/pkg/hunter"
	rules2 "github.com/brittonhayes/pillager/pkg/rules"
	"github.com/spf13/afero"
)

func main() {
	// Create a new hunter config
	c := hunter2.NewConfig(afero.NewOsFs(), ".", true, rules2.Load(""), hunter2.StringToFormat("JSON"))

	// Create a new hunter from the config
	h := hunter2.NewHunter(c)

	// Start hunting
	_ = h.Hunt()
}
