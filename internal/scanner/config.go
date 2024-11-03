package scanner

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/brittonhayes/pillager"
	"github.com/rs/zerolog/log"
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
	v.SetDefault("scan_path", ".")
	v.SetDefault("template", "")
	v.SetDefault("workers", runtime.NumCPU())
	v.SetDefault("redact", false)
	v.SetDefault("reporter", "json")

	// Rules and allowlist defaults
	v.SetDefault("rules", convertGitleaksRules())
	v.SetDefault("allowlist.paths", []string{})
	v.SetDefault("allowlist.regexes", []string{})
	v.SetDefault("allowlist.commits", []string{})

	return &ConfigLoader{v: v}
}

func convertGitleaksRules() []pillager.Rule {
	var defaultConfig config.Config
	if err := toml.Unmarshal([]byte(config.DefaultConfig), &defaultConfig); err != nil {
		log.Fatal().Err(err).Msg("failed to parse default rules")
	}

	var rules []pillager.Rule
	for _, rule := range defaultConfig.Rules {
		rules = append(rules, pillager.Rule{
			ID:          rule.RuleID,
			Description: rule.Description,
			Regex:       rule.Regex.String(),
			Tags:        rule.Tags,
		})
	}

	return rules
}

// LoadConfig attempts to load configuration from a file
func (c *ConfigLoader) LoadConfig(configPath string) (*pillager.Options, error) {
	if configPath != "" {
		// Use specified config file
		ext := filepath.Ext(configPath)
		if ext == "" {
			return nil, fmt.Errorf("config file must have an extension (.yaml, .toml, or .json)")
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
		c.v.AddConfigPath("/etc/pillager/")

		c.v.ReadInConfig()
	}

	// Create options from config
	opts := &pillager.Options{
		Workers:  c.v.GetInt("workers"),
		Verbose:  c.v.GetBool("verbose"),
		Template: c.v.GetString("template"),
		Redact:   c.v.GetBool("redact"),
		Reporter: c.v.GetString("reporter"),
		Rules:    c.v.Get("rules").([]pillager.Rule),
		Allowlist: pillager.Allowlist{
			Paths:   c.v.GetStringSlice("allowlist.paths"),
			Regexes: c.v.GetStringSlice("allowlist.regexes"),
			Commits: c.v.GetStringSlice("allowlist.commits"),
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
	if flags.ScanPath != "" {
		opts.ScanPath = flags.ScanPath
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
	if len(flags.Allowlist.Commits) > 0 {
		opts.Allowlist.Commits = flags.Allowlist.Commits
	}
}
