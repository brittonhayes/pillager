// Package rules enables the parsing of Gitleaks rulesets
package rules

import (
	_ "embed"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	ErrReadConfig = "Failed to read config"
)

var (
	//go:embed rules_simple.toml
	RulesDefault string

	//go:embed rules_strict.toml
	RulesStrict string
)

type Loader struct {
	loader config.ViperConfig
}

type LoaderOption func(*Loader)

// NewLoader creates a configuration
// loader.
func NewLoader(opts ...LoaderOption) *Loader {
	var loader Loader
	_, err := toml.Decode(RulesDefault, &loader.loader)
	if err != nil {
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
		_, err := toml.Decode(RulesStrict, &l.loader)
		if err != nil {
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

// FromFile decodes the configuration
// from a local file.
func FromFile(file string) LoaderOption {
	return func(l *Loader) {
		_, err := toml.DecodeFile(file, &l.loader)
		if err != nil {
			log.Fatal().Err(err).Msg(ErrReadConfig)
		}
	}
}
