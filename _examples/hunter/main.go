package main

import (
	"os"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/rs/zerolog"
)

func main() {
	err := example()
	if err != nil {
		panic(err)
	}
}

func example() error {
	opts := []pillager.ConfigOption{
		pillager.WithLogLevel(zerolog.DebugLevel),
	}

	// Create a new hunter config
	p, err := hunter.New(opts...)
	if err != nil {
		return err
	}

	// Start hunting
	results, err := p.Hunt()
	if err != nil {
		return err
	}

	// Report results
	err = p.Report(os.Stdout, results)
	if err != nil {
		return err
	}

	return nil
}
