package scanner

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/brittonhayes/pillager"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
)

// ConfigLoader handles loading configuration from files
type ConfigLoader struct {
	v *viper.Viper
}

// NewConfigLoader creates a new configuration loader
func NewConfigLoader() *ConfigLoader {
	v := viper.New()
	v.SetDefault("verbose", false)
	v.SetDefault("path", ".")
	v.SetDefault("template", "")
	v.SetDefault("workers", runtime.NumCPU())
	v.SetDefault("redact", false)
	v.SetDefault("reporter", "json")

	return &ConfigLoader{v: v}
}

func convertDefaultConfig() (*pillager.Options, error) {
	var defaultConfig config.Config

	if err := toml.Unmarshal([]byte(config.DefaultConfig), &defaultConfig); err != nil {
		return nil, errors.Wrap(err, "failed to parse default rules")
	}

	var opts pillager.Options

	opts.Rules = gitleaksToPillagerRules(defaultConfig.Rules)
	opts.Allowlist = gitleaksToPillagerAllowlist(defaultConfig.Allowlist)

	return &opts, nil
}

// LoadConfig attempts to load configuration from a file
func (c *ConfigLoader) LoadConfig(configPath string) (*pillager.Options, error) {

	// Rules and allowlist defaults
	defaultConfig, err := convertDefaultConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert default rules")
	}

	c.v.SetDefault("rules", defaultConfig.Rules)
	c.v.SetDefault("allowlist.paths", defaultConfig.Allowlist.Paths)
	c.v.SetDefault("allowlist.regexes", defaultConfig.Allowlist.Regexes)

	if configPath != "" {
		// Use specified config file
		ext := filepath.Ext(configPath)
		if ext != ".toml" {
			return nil, fmt.Errorf("config file must have an extension .toml")
		}
		c.v.SetConfigType(ext[1:])
		c.v.SetConfigFile(configPath)

		if err := c.v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	} else {
		// Search for config in default locations
		c.v.SetConfigName("pillager")
		c.v.AddConfigPath(".")
		c.v.AddConfigPath("$HOME/.pillager")
		c.v.AddConfigPath("$HOME/.config/pillager")

		c.v.ReadInConfig()
	}

	// Create options from config
	opts := &pillager.Options{
		Path:     c.v.GetString("path"),
		Workers:  c.v.GetInt("workers"),
		Verbose:  c.v.GetBool("verbose"),
		Template: c.v.GetString("template"),
		Redact:   c.v.GetBool("redact"),
		Reporter: c.v.GetString("reporter"),
		Allowlist: pillager.Allowlist{
			Paths:   c.v.GetStringSlice("allowlist.paths"),
			Regexes: c.v.GetStringSlice("allowlist.regexes"),
		},
	}

	// Unmarshal rules if they exist
	var rules []pillager.Rule
	if err := c.v.UnmarshalKey("rules", &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules configuration: %w", err)
	}
	opts.Rules = rules

	return opts, nil
}

// MergeWithFlags merges configuration with command line flags
func (c *ConfigLoader) MergeWithFlags(opts *pillager.Options, flags *pillager.Options) {
	if flags.Verbose {
		opts.Verbose = flags.Verbose
	}
	if flags.Redact {
		opts.Redact = flags.Redact
	}
	if flags.Workers > 0 {
		opts.Workers = flags.Workers
	}
	if flags.Reporter != "" {
		opts.Reporter = flags.Reporter
	}
	if flags.Template != "" {
		opts.Template = flags.Template
	}
	if flags.Path != "" {
		opts.Path = flags.Path
	}
	// Merge rules if provided
	if len(flags.Rules) > 0 {
		opts.Rules = flags.Rules
	}
	// Merge allowlist if provided
	if len(flags.Allowlist.Paths) > 0 {
		opts.Allowlist.Paths = flags.Allowlist.Paths
	}
	if len(flags.Allowlist.Regexes) > 0 {
		opts.Allowlist.Regexes = flags.Allowlist.Regexes
	}
}
