// Package cmd contains the command line logic
//
// The cmd package is the primary consumer of all packages in the /pkg directory
package cmd

import (
	"runtime"

	"github.com/brittonhayes/pillager/hunter"
	"github.com/brittonhayes/pillager/rules"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	rulesConfig string
	output      string
	templ       string
	workers     int
)

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Example: `
# Run a basic hunt
pillager hunt .

# Print out results in JSON format
pillager hunt ./example -f json

# Print out results in YAML format
pillager hunt . -f yaml

# Print out results with a custom inline template
pillager hunt . --template "{{ range .Leaks}}Leak: {{.Line}}{{end}}"

# Print out results with a custom template file
pillager hunt ./example --template "$(cat templates/simple.tmpl)"
`,
	Args: cobra.ExactArgs(1),
	RunE: startHunt(),
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers to create")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "toggle verbose output")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules", "r", "", "path to gitleaks rules.toml config")
	huntCmd.Flags().StringVarP(&output, "format", "f", "json", "set output format (json, yaml)")
	huntCmd.Flags().StringVarP(
		&templ,
		"template",
		"t",
		"",
		"set go text/template string for output format",
	)
}

func startHunt() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		c := hunter.NewConfig(
			afero.NewOsFs(),
			args[0],
			verbose,
			rules.Load(rulesConfig),
			hunter.StringToFormat(output),
			templ,
			workers,
		)
		h := hunter.NewHunter(c)
		return h.Hunt()
	}
}
