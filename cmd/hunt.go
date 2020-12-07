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
	financial  bool
	github     bool
	telephone  bool
	email      bool
	address    bool
	monochrome bool
	verbose    bool
	output     string
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
	huntCmd.Flags().BoolVarP(&financial, "financial", "f", false, "filter for financial information")
	huntCmd.Flags().BoolVarP(&github, "github", "g", false, "filter for github information")
	huntCmd.Flags().BoolVarP(&telephone, "telephone", "t", false, "filter for telephone information")
	huntCmd.Flags().BoolVarP(&email, "email", "e", false, "filter for email information")
	huntCmd.Flags().BoolVarP(&address, "address", "a", false, "filter for address information")
	huntCmd.Flags().BoolVarP(&monochrome, "monochrome", "m", false, "toggle colorful output")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "toggle verbose output")
	huntCmd.Flags().StringVarP(&output, "output", "o", "yaml", "set output format (json, yaml)")
}

func StartHunt() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		fs := afero.NewOsFs()
		c := hunter.Config{
			System:     fs,
			Patterns:   hunter.FilterResults(financial, github, telephone, email, address),
			BasePath:   hunter.CheckPath(fs, args[0]),
			Monochrome: monochrome,
			Verbose:    verbose,
			Format:     hunter.StringToFormat(output),
		}
		h := hunter.NewHunter(&c)
		err := h.Hunt()
		if err != nil {
			return err
		}
		return nil
	}
}
