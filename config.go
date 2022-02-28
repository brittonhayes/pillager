//go:generate golangci-lint run ./...
//go:generate gomarkdoc ./pkg/hunter/...
//go:generate gomarkdoc ./pkg/rules/...
//go:generate gomarkdoc ./pkg/format/...
package pillager

import (
	"errors"
	"os"
	"runtime"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/brittonhayes/pillager/internal/validate"
	"github.com/brittonhayes/pillager/pkg/format"
	"github.com/brittonhayes/pillager/pkg/rules"
	"github.com/spf13/afero"
	gitleaks "github.com/zricethezav/gitleaks/v7/config"
)

// Config takes all of the configurable
// parameters for a Hunter.
type Config struct {
	Filesystem afero.Fs
	Style      format.Style
	Gitleaks   gitleaks.Config

	ScanPath string
	Verbose  bool
	Debug    bool
	Workers  int
	Template string
}

type ConfigOption func(*Config)

func NewConfig(opts ...ConfigOption) *Config {
	var (
		defaultFS       = afero.NewOsFs()
		defaultVerbose  = false
		defaultScanPath = "."
		defaultStyle    = format.StyleJSON
		defaultWorkers  = runtime.NumCPU()
		defaultGitleaks = rules.NewLoader().Load()
		defaultTemplate = ""
		defaultLogLevel = zerolog.ErrorLevel
	)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.SetGlobalLevel(defaultLogLevel)
	config := &Config{
		ScanPath:   defaultScanPath,
		Filesystem: defaultFS,
		Style:      defaultStyle,
		Workers:    defaultWorkers,
		Gitleaks:   defaultGitleaks,
		Verbose:    defaultVerbose,
		Template:   defaultTemplate,
	}

	for _, opt := range opts {
		opt(config)
	}

	if err := config.validate(); err != nil {
		log.Fatal().Err(err).Send()
	}

	return config
}

func WithFS(fs afero.Fs) ConfigOption {
	return func(c *Config) {
		c.Filesystem = fs
	}
}

func WithScanPath(path string) ConfigOption {
	return func(c *Config) {
		c.ScanPath = validate.Path(c.Filesystem, c.ScanPath)
	}
}

func WithLogLevel(level zerolog.Level) ConfigOption {
	return func(c *Config) {
		zerolog.SetGlobalLevel(level)
	}
}

func WithVerbose(verbose bool) ConfigOption {
	return func(c *Config) {
		c.Verbose = verbose
	}
}

func WithWorkers(count int) ConfigOption {
	return func(c *Config) {
		c.Workers = count
	}
}

func WithStyle(style format.Style) ConfigOption {
	return func(c *Config) {
		if c.Template != "" {
			c.Style = format.StyleCustom
			return
		}

		c.Style = style
	}
}

func WithTemplate(template string) ConfigOption {
	return func(c *Config) {
		c.Style = format.StyleCustom
		c.Template = template
	}
}

func WithGitleaksConfig(g gitleaks.Config) ConfigOption {
	return func(c *Config) {
		c.Gitleaks = g
	}
}

func (c *Config) validate() error {
	if c.Filesystem == nil {
		return errors.New("missing filesystem in Config")
	}

	if c.Gitleaks.Rules == nil {
		return errors.New("no gitleaks rules provided")
	}

	return nil
}
