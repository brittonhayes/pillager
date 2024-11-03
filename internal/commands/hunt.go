// Package commands contains the command line logic.
//
// The commands package is the primary consumer of all packages in the /pkg directory.
package commands

import (
	"fmt"
	"os"
	"runtime"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/internal/scanner"
	"github.com/rs/zerolog"
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
	config      string
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
		if level != "" {
			lvl, err := zerolog.ParseLevel(level)
			if err != nil {
				return fmt.Errorf("invalid log level: %w", err)
			}
			zerolog.SetGlobalLevel(lvl)
		}

		configLoader := scanner.NewConfigLoader()
		opts, err := configLoader.LoadConfig(config)
		if err != nil {
			if config != "" {
				return fmt.Errorf("failed to load config: %w", err)
			}
			opts = &pillager.Options{
				ScanPath: args[0],
				Workers:  runtime.NumCPU(),
				Verbose:  false,
				Template: "",
				Redact:   false,
				Reporter: "json",
			}
		}

		// Merge command line flags with config file
		flagOpts := &pillager.Options{
			ScanPath: args[0],
			Redact:   redact,
			Verbose:  verbose,
			Workers:  workers,
			Reporter: reporter,
			Template: templ,
		}
		configLoader.MergeWithFlags(opts, flagOpts)

		s, err := scanner.NewGitleaksScanner(*opts)
		if err != nil {
			return fmt.Errorf("failed to create scanner: %w", err)
		}

		// if interactive {
		// 	return runInteractive(scan)
		// }

		results, err := s.Scan(args[0])
		if err != nil {
			return err
		}

		return s.Reporter().Report(os.Stdout, results)
	},
}

// func runInteractive(h *scanner.Hunter) error {
// 	m := model.NewModel(h)
// 	p := tea.NewProgram(m, tea.WithAltScreen())
// 	return p.Start()
// }

func init() {
	rootCmd.AddCommand(huntCmd)
	huntCmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "run in interactive mode")
	huntCmd.Flags().IntVarP(&workers, "workers", "w", runtime.NumCPU(), "number of concurrent workers")
	huntCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enable scanner verbose output")
	huntCmd.Flags().StringVarP(&level, "log-level", "l", "info", "set logging level")
	huntCmd.Flags().StringVarP(&config, "config", "c", "", "path to pillager config file")
	huntCmd.Flags().StringVarP(&rulesConfig, "rules", "r", "", "path to gitleaks rules.toml config")
	huntCmd.Flags().StringVarP(&reporter, "format", "f", "json", "set secret reporter format (json, yaml)")
	huntCmd.Flags().BoolVar(&redact, "redact", false, "redact secret from results")
	huntCmd.Flags().StringVarP(&templ, "template", "t", "", "set go text/template string for output format")
}
