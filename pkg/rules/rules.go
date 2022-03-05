// Package rules enables the parsing of Gitleaks rulesets.
package rules

import (
	_ "embed"

	"github.com/BurntSushi/toml"
	"github.com/brittonhayes/pillager/internal/validate"
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
)

// ErrReadConfig is the custom error message used if an error is encountered
// reading the gitleaks config.
const ErrReadConfig = "Failed to read gitleaks config"

// These strings contain default configs. They are initialized at compile time via go:embed.
var (
	//go:embed rules_simple.toml
	RulesDefault string

	//go:embed rules_strict.toml
	RulesStrict string
)

// Loader represents a gitleaks config loader.
type Loader struct {
	loader config.ViperConfig
}

// LoaderOption sets a parameter for the gitleaks config loader.
type LoaderOption func(*Loader)

// NewLoader creates a Loader instance.
func NewLoader(opts ...LoaderOption) *Loader {
	var loader Loader
	if _, err := toml.Decode(RulesDefault, &loader.loader); err != nil {
		log.Fatal().Err(err).Msg(ErrReadConfig)
	}

	for _, opt := range opts {
		opt(&loader)
	}

	return &loader
}

// WithStrict enables more strict pillager scanning.
func (l *Loader) WithStrict() LoaderOption {
	return func(l *Loader) {
		if _, err := toml.Decode(RulesStrict, &l.loader); err != nil {
			log.Fatal().Err(err).Msg(ErrReadConfig)
		}
	}
}

// Load parses the gitleaks configuration.
func (l *Loader) Load() config.Config {
	config, err := l.loader.Translate()
	if err != nil {
		log.Fatal().Err(err).Msg(ErrReadConfig)
	}

	return config
}

// WithFile decodes a gitleaks config from a local file.
func WithFile(file string) LoaderOption {
	return func(l *Loader) {
		if file == "" {
			if _, err := toml.Decode(RulesDefault, &l.loader); err != nil {
				log.Fatal().Err(err).Msg(ErrReadConfig)
			}
			return
		}

		if validate.PathExists(file) {
			if _, err := toml.DecodeFile(file, &l.loader); err != nil {
				log.Fatal().Err(err).Msg(ErrReadConfig)
			}
			return
		}

		log.Fatal().Msgf("invalid - rules file '%s' does not exist", file)
	}
}
