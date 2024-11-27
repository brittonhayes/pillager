package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/scanner"
	"github.com/gookit/color"
	"github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string
var (
	verbose  bool
	level    string
	settings bool
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "pillager",
	Short: "Pillage systems for sensitive information",
	Long: color.Cyan.Text(`
	██▓███   ██▓ ██▓     ██▓    ▄▄▄        ▄████ ▓█████  ██▀███
	▓██░  ██▒▓██▒▓██▒    ▓██▒   ▒████▄     ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
	▓██░ ██▓▒▒██▒▒██░    ▒██░   ▒██  ▀█▄  ▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
	▒██▄█▓▒ ▒░██░▒██░    ▒██░   ░██▄▄▄▄██ ░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄
	▒██▒ ░  ░░██░░██████▒░██████▒▓█   ▓██▒░▒▓███▀▒░▒████▒░██▓ ▒██▒
	▒▓▒░ ░  ░░▓  ░ ▒░▓  ░░ ▒░▓  ░▒▒   ▓▒█░ ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
	░▒ ░      ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ▒   ▒▒ ░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
	░░        ▒ ░  ░ ░     ░ ░    ░   ▒   ░ ░   ░    ░     ░░   ░
	░      ░  ░    ░  ░     ░  ░      ░    ░  ░   ░

			Pillage filesystems for loot.
`),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by pillager.pillager(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pillager.toml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable scanner verbose output")
	rootCmd.PersistentFlags().StringVarP(&level, "log-level", "l", "info", "set logging level")
	rootCmd.PersistentFlags().BoolVarP(&settings, "settings", "s", false, "print pillager settings")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in multiple locations
		viper.SetConfigName("pillager")
		viper.AddConfigPath(".")
		viper.AddConfigPath(home)
		viper.AddConfigPath(filepath.Join(home, ".pillager"))
		viper.AddConfigPath(filepath.Join(home, ".config", "pillager"))
		viper.SetConfigType("toml")
	}

	// Read environment variables
	viper.SetEnvPrefix("PILLAGER")
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err == nil {
		log.Debug().Msgf("Using config file: %q", viper.ConfigFileUsed())
	}

	// Set log level
	if level := viper.GetString("log_level"); level != "" {
		lvl, err := zerolog.ParseLevel(level)
		if err != nil {
			log.Error().Err(err).Msg("invalid log level")
		} else {
			zerolog.SetGlobalLevel(lvl)
		}
	}

	if viper.ConfigFileUsed() == "" {
		log.Debug().Msg("no config file found, using defaults")
		opts, err := scanner.ConvertDefaultConfig()
		if err != nil {
			log.Error().Err(err).Msg("failed to convert default config")
		}

		viper.MergeConfigMap(map[string]interface{}{
			"verbose":   opts.Verbose,
			"path":      opts.Path,
			"template":  opts.Template,
			"workers":   opts.Workers,
			"redact":    opts.Redact,
			"format":    opts.Format,
			"dedupe":    opts.Dedup,
			"entropy":   opts.Entropy,
			"rules":     opts.Rules,
			"allowlist": opts.Allowlist,
		})
	}

	if settings {
		unmarshaled, err := json.Marshal(viper.AllSettings())
		if err != nil {
			log.Error().Err(err).Msg("failed to marshal default config")
		}

		fmt.Println(string(unmarshaled))
		os.Exit(0)
	}
}

// setupConfig returns a configured Options struct
func setupConfig() (*pillager.Options, error) {
	return scanner.LoadConfig()
}
