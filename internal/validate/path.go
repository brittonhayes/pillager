package validate

import (
	"github.com/rs/zerolog/log"

	"github.com/spf13/afero"
)

// Path checks if a file at the given path exists and returns it if so,
// otherwise returns a default path.
func Path(fs afero.Fs, path string) string {
	ok, err := afero.Exists(fs, path)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	if ok {
		return path
	}

	log.Fatal().Msg("no valid path provided")
	return "."
}
