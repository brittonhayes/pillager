// Package cmd contains the command line logic
//
// The cmd package is the primary consumer of all packages in the /pkg directory
package cmd

import (
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	rulesConfig string
	output      string
)

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Args:  cobra.MinimumNArgs(1),
	RunE:  StartHunt(),
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "toggle verbose output")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules-config", "r", "", "path to gitleaks rules config")
	huntCmd.Flags().StringVarP(&output, "output", "o", "yaml", "set output format (json, yaml)")
}

func StartHunt() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fs := afero.NewOsFs()
		c := hunter.Config{
			System:   fs,
			BasePath: hunter.CheckPath(fs, args[0]),
			Verbose:  verbose,
			Format:   hunter.StringToFormat(output),
			Rules:    hunter.LoadRules(rulesConfig),
		}
		h := hunter.NewHunter(&c)
		err := h.Hunt()
		if err != nil {
			return err
		}
		return nil
	}
}
