package hunter

import (
	"fmt"

	"github.com/brittonhayes/pillager/internal/validate"
	"github.com/brittonhayes/pillager/rules"
	"github.com/spf13/afero"
	gitleaks "github.com/zricethezav/gitleaks/v7/config"
)

var _ Configer = &Config{}

// Config takes all of the configurable
// parameters for a Hunter
type Config struct {
	System   afero.Fs
	BasePath string
	Verbose  bool
	Workers  int
	Gitleaks gitleaks.Config
	Format   Format
	Template string
}

type Configer interface {
	Default() *Config
	Validate() (err error)
}

// NewConfig generates a new config for the Hunter
func NewConfig(fs afero.Fs, path string, verbose bool, gitleaks gitleaks.Config, format Format, template string, workers int) *Config {
	p := validate.New().Path(fs, path)
	return &Config{
		System:   fs,
		BasePath: p,
		Verbose:  verbose,
		Gitleaks: gitleaks,
		Format:   format,
		Template: template,
		Workers:  workers,
	}
}

// Default loads the default configuration
// for the Hunter
func (c *Config) Default() *Config {
	fs := afero.NewOsFs()
	v := validate.New()
	return &Config{
		System:   fs,
		BasePath: v.Path(fs, "."),
		Verbose:  false,
		Template: DefaultTemplate,
		Gitleaks: rules.Load(""),
		Format:   JSONFormat,
	}
}

func (c *Config) Validate() (err error) {
	if c.System == nil {
		err = fmt.Errorf("missing filesystem in Hunter Config")
	}

	if c.Gitleaks.Rules == nil {
		err = fmt.Errorf("no gitleaks config provided")
	}
	return
}
