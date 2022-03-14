package main

import (
	"os"

	"github.com/brittonhayes/pillager/pkg/format"
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Create a new hunter config
	h, err := hunter.New(
		hunter.WithScanPath("."),
		hunter.WithWorkers(2),
		hunter.WithFormat(format.Simple{}),
		hunter.WithLogLevel(zerolog.DebugLevel.String()),
	)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	// Start hunting
	results, err := h.Hunt()
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	// Report results
	if err = h.Report(os.Stdout, results); err != nil {
		log.Fatal().Err(err).Send()
	}
}
