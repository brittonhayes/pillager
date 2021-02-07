package cmd

import (
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
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
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.pillager.toml)")
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

		// Search config in home directory with name ".pillager" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("toml")
		viper.SetConfigName(".pillager")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
