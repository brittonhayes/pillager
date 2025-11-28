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
	format   string
	dedupe   bool
	entropy  float32
}

// NewGitleaksScanner creates a new scanner using gitleaks
func NewGitleaksScanner(options pillager.Options) (Scanner, error) {
	scanner := &GitleaksScanner{
		format: options.Format,
	}

	cfg := config.Config{
		Allowlist: convertToGitleaksAllowlist(options.Allowlist),
		Rules:     pillagerToGitleaksRules(options.Rules),
		Path:      options.Path,
	}

	scanner.detector = detect.NewDetector(cfg)
	scanner.detector.Verbose = options.Verbose
	scanner.detector.Redact = options.Redact
	scanner.dedupe = options.Dedup
	scanner.entropy = float32(options.Entropy)

	return scanner, nil
}

// Reporter returns the reporter for the scanner
func (g *GitleaksScanner) Reporter() report.Reporter {
	return report.StringToReporter(g.format)
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
		Tags:        f.Tags,
	}
	return finding
}

// Scan implements the Scanner interface
func (g *GitleaksScanner) Scan() ([]pillager.Finding, error) {
	findings, err := g.detector.DetectFiles(g.ScanPath())
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan files")
	}

	var pillagerFindings []pillager.Finding
	for _, f := range findings {
		if f.Entropy < g.entropy {
			continue
		}
		pillagerFindings = append(pillagerFindings, g.Translate(f))
	}

	if len(pillagerFindings) == 0 {
		return pillagerFindings, nil
	}

	if g.dedupe {
		pillagerFindings = DedupFindings(pillagerFindings)
	}

	return pillagerFindings, nil
}

func convertToGitleaksAllowlist(a pillager.Allowlist) config.Allowlist {
	paths := []*regexp.Regexp{}
	for _, path := range a.Paths {
		p, err := regexp.Compile(path)
		if err != nil {
			log.Fatal().Err(err).
				Str("pattern", path).
				Msg("failed to compile allowlist path regex")
		}
		paths = append(paths, p)
	}

	regexes := []*regexp.Regexp{}
	for _, regex := range a.Regexes {
		r, err := regexp.Compile(regex)
		if err != nil {
			log.Fatal().Err(err).
				Str("pattern", regex).
				Msg("failed to compile allowlist regex pattern")
		}
		regexes = append(regexes, r)
	}

	return config.Allowlist{
		Paths:   paths,
		Regexes: regexes,
	}
}

func gitleaksToPillagerAllowlist(a config.Allowlist) pillager.Allowlist {
	paths := []string{}
	for _, path := range a.Paths {
		paths = append(paths, path.String())
	}

	regexes := []string{}
	for _, regex := range a.Regexes {
		regexes = append(regexes, regex.String())
	}

	stopWords := []string{}
	stopWords = append(stopWords, a.StopWords...)

	return pillager.Allowlist{Paths: paths, Regexes: regexes, StopWords: stopWords}
}

func gitleaksToPillagerRules(rules []*config.Rule) []pillager.Rule {
	converted := []pillager.Rule{}
	for _, rule := range rules {
		r := gitleaksToPillagerRule(rule)
		converted = append(converted, r)
	}
	return converted
}

func gitleaksToPillagerRule(rule *config.Rule) pillager.Rule {
	return pillager.Rule{
		ID:          rule.RuleID,
		Description: rule.Description,
		Regex:       rule.Regex.String(),
		Tags:        rule.Tags,
		Allowlist:   gitleaksToPillagerAllowlist(rule.Allowlist),
	}
}

func pillagerToGitleaksRules(rules []pillager.Rule) []*config.Rule {
	converted := []*config.Rule{}
	for _, rule := range rules {
		r := pillagerToGitleaksRule(rule)
		converted = append(converted, r)
	}
	return converted
}

func pillagerToGitleaksRule(rule pillager.Rule) *config.Rule {
	path, err := regexp.Compile(rule.Path)
	if err != nil {
		log.Fatal().Err(err).
			Str("rule_id", rule.ID).
			Str("pattern", rule.Path).
			Msg("failed to compile rule path regex")
	}

	regex, err := regexp.Compile(rule.Regex)
	if err != nil {
		log.Fatal().Err(err).
			Str("rule_id", rule.ID).
			Str("pattern", rule.Regex).
			Msg("failed to compile rule regex pattern")
	}

	return &config.Rule{
		RuleID:      rule.ID,
		Path:        path,
		Description: rule.Description,
		Regex:       regex,
		Keywords:    rule.Keywords,
		Tags:        rule.Tags,
		Allowlist:   convertToGitleaksAllowlist(rule.Allowlist),
	}
}
