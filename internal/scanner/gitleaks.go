package scanner

import (
	"regexp"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/report"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	output "github.com/zricethezav/gitleaks/v8/report"
)

// GitleaksScanner implements the Scanner interface using gitleaks
type GitleaksScanner struct {
	detector *detect.Detector
	reporter string
}

// NewGitleaksScanner creates a new scanner using gitleaks
func NewGitleaksScanner(options pillager.Options) (Scanner, error) {
	scanner := &GitleaksScanner{
		reporter: options.Reporter,
	}

	cfg := config.Config{
		Allowlist: scanner.convertAllowlist(options.Allowlist),
		Rules:     scanner.convertRules(options.Rules),
		Path:      options.ScanPath,
	}

	scanner.detector = detect.NewDetector(cfg)
	scanner.detector.Verbose = options.Verbose
	scanner.detector.Redact = options.Redact

	return scanner, nil
}

// Reporter returns the reporter for the scanner
func (g *GitleaksScanner) Reporter() report.Reporter {
	return report.StringToReporter(g.reporter)
}

// ScanPath returns the path that the scanner is scanning
func (g *GitleaksScanner) ScanPath() string {
	return g.detector.Config.Path
}

func (g *GitleaksScanner) Translate(f output.Finding) pillager.Finding {
	finding := pillager.Finding{
		Description: f.Description,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Match:       f.Match,
		Secret:      f.Secret,
		File:        f.File,
		Entropy:     f.Entropy,
		RuleID:      f.RuleID,
	}
	return finding
}

// Scan implements the Scanner interface
func (g *GitleaksScanner) Scan(path string) ([]pillager.Finding, error) {
	findings, err := g.detector.DetectFiles(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan files")
	}

	var pillagerFindings []pillager.Finding
	for _, f := range findings {
		pillagerFindings = append(pillagerFindings, g.Translate(f))
	}

	return pillagerFindings, nil
}

func (g *GitleaksScanner) convertAllowlist(a pillager.Allowlist) config.Allowlist {
	paths := []*regexp.Regexp{}
	for _, path := range a.Paths {
		paths = append(paths, regexp.MustCompile(path))
	}

	regexes := []*regexp.Regexp{}
	for _, regex := range a.Regexes {
		regexes = append(regexes, regexp.MustCompile(regex))
	}

	return config.Allowlist{
		Paths:   paths,
		Regexes: regexes,
		Commits: a.Commits,
	}
}

func (g *GitleaksScanner) convertRules(rules []pillager.Rule) []*config.Rule {
	converted := []*config.Rule{}

	for _, rule := range rules {
		regex, err := regexp.Compile(rule.Regex)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to compile regex for rule")
		}

		path, err := regexp.Compile(rule.Path)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to compile path for rule")
		}

		converted = append(converted, &config.Rule{
			RuleID:      rule.ID,
			Path:        path,
			Description: rule.Description,
			Regex:       regex,
			Keywords:    rule.Keywords,
			Tags:        rule.Tags,
			Allowlist:   g.convertAllowlist(rule.Allowlist),
		})
	}

	return converted
}
