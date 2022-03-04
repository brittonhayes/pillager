package hunter

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

	"github.com/zricethezav/gitleaks/v8/config"
)

// Config takes all of the configurable parameters for a Hunter.
type Config struct {
	Filesystem afero.Fs
	Reporter   format.Reporter
	Gitleaks   config.Config

	ScanPath string
	Verbose  bool
	Redact   bool
	Debug    bool
	Workers  int
	Template string
}

// ConfigOption is a convenient type alias for func(*Config).
type ConfigOption func(*Config)

// NewConfig creates a Config instance.
func NewConfig(opts ...ConfigOption) *Config {
	var (
		defaultFS       = afero.NewOsFs()
		defaultVerbose  = false
		defaultScanPath = "."
		defaultReporter = format.JSON{}
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
		Reporter:   defaultReporter,
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
		if validate.PathExists(path) {
			c.ScanPath = path
			return
		}

		currentDir, err := os.Getwd()
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get current dir")
		}

		log.Error().Msgf("scan path %q not found, defaulting to %q", path, currentDir)
		c.ScanPath = currentDir
	}
}

func WithLogLevel(level string) ConfigOption {
	return func(c *Config) {
		lvl, err := zerolog.ParseLevel(level)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		zerolog.SetGlobalLevel(lvl)
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

func WithRedact(redact bool) ConfigOption {
	return func(c *Config) {
		c.Redact = redact
	}
}

func WithFormat(reporter format.Reporter) ConfigOption {
	return func(c *Config) {
		if c.Template != "" {
			custom := &format.Custom{}
			custom.WithTemplate(c.Template)
			c.Reporter = custom
			return
		}

		c.Reporter = reporter
	}
}

func WithTemplate(template string) ConfigOption {
	return func(c *Config) {
		c.Reporter = format.Custom{}
		c.Template = template
	}
}

func WithGitleaksConfig(g config.Config) ConfigOption {
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
