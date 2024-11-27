package scanner

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"github.com/brittonhayes/pillager"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ConvertDefaultConfig() (*pillager.Options, error) {
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
func LoadConfig() (*pillager.Options, error) {
	// Rules and allowlist defaults
	defaultConfig, err := ConvertDefaultConfig()
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert default rules")
	}

	viper.SetDefault("rules", defaultConfig.Rules)
	viper.SetDefault("allowlist.paths", defaultConfig.Allowlist.Paths)
	viper.SetDefault("allowlist.regexes", defaultConfig.Allowlist.Regexes)

	// Create options from config
	opts := &pillager.Options{
		Path:     viper.GetString("path"),
		Workers:  viper.GetInt("workers"),
		Verbose:  viper.GetBool("verbose"),
		Template: viper.GetString("template"),
		Redact:   viper.GetBool("redact"),
		Format:   viper.GetString("format"),
		Dedup:    viper.GetBool("dedupe"),
		Entropy:  viper.GetFloat64("entropy"),
		Allowlist: pillager.Allowlist{
			Paths:   viper.GetStringSlice("allowlist.paths"),
			Regexes: viper.GetStringSlice("allowlist.regexes"),
		},
	}

	// Unmarshal rules if they exist
	var rules []pillager.Rule
	if err := viper.UnmarshalKey("rules", &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules configuration: %w", err)
	}
	opts.Rules = rules

	return opts, nil
}
