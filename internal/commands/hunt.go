// Package commands contains the command line logic.
//
// The commands package is the primary consumer of all packages in the /pkg directory.
package commands

import (
	"os"
	"runtime"

	"github.com/brittonhayes/pillager/pkg/format"
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/brittonhayes/pillager/pkg/rules"
	"github.com/brittonhayes/pillager/pkg/tui/model"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var (
	verbose     bool
	redact      bool
	level       string
	rulesConfig string
	reporter    string
	templ       string
	workers     int
	interactive bool
)

// huntCmd represents the hunt command.
var huntCmd = &cobra.Command{
	Use:   "hunt [directory]",
	Short: "Hunt for loot",
	Long:  "Hunt inside the file system for valuable information",
	Example: `
	Basic:
		pillager hunt .
	
	JSON Format:
		pillager hunt ./example -f json
	
	YAML Format:
		pillager hunt . -f yaml
	
	HTML Format:
		pillager hunt . -f html > results.html
	
	HTML Table Format:
		pillager hunt . -f html-table > results.html
	
	Markdown Table Format:
		pillager hunt . -f table > results.md
	
	Custom Go Template Format:
		pillager hunt . --template "{{ range .}}Secret: {{.Secret}}{{end}}"
	
	Custom Go Template Format from Template File:
		pillager hunt ./example --template "$(cat pkg/templates/simple.tmpl)"
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read gitleaks config from file
		// or fallback to default
		gitleaksConfig := rules.NewLoader(
			rules.WithFile(rulesConfig),
		).Load()

		h, err := hunter.New(
			hunter.WithGitleaksConfig(gitleaksConfig),
			hunter.WithScanPath(args[0]),
			hunter.WithWorkers(workers),
			hunter.WithVerbose(verbose),
			hunter.WithTemplate(templ),
			hunter.WithRedact(redact),
			hunter.WithFormat(format.StringToReporter(reporter)),
			hunter.WithLogLevel(level),
		)
		if err != nil {
			return err
		}

		if interactive {
			return runInteractive(h)
		}

		results, err := h.Hunt()
		if err != nil {
			return err
		}

		if err = h.Report(os.Stdout, results); err != nil {
			return err
		}

		return nil
	},
}

func runInteractive(h *hunter.Hunter) error {
	m := model.NewModel(h)
	p := tea.NewProgram(m, tea.WithAltScreen())
	return p.Start()
}

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "run in interactive mode")
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable scanner verbose output")
	huntCmd.Flags().StringVarP(&level, "log-level", "l", "error", "set logging level")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules", "r", "", "path to gitleaks rules.toml config")
	huntCmd.Flags().StringVarP(&reporter, "format", "f", "json", "set secret reporter (json, yaml)")
	huntCmd.Flags().BoolVar(&redact, "redact", false, "redact secret from results")
	huntCmd.Flags().StringVarP(&templ, "template", "t", "", "set go text/template string for output format")
}
