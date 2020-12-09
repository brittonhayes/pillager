package hunter

import (
	"bufio"
	"fmt"
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"log"
	"os"
	"regexp"
	"runtime"
	"sync"
)

// Hunter holds the required fields to implement
// the Hunting interface and utilize the hunter package
type Hunter struct {
	Config *Config
	Hound  *Hound
}

var _ Hunting = Hunter{}

// Hunting is the primary API interface for the hunter package
type Hunting interface {
	Hunt() error
	Inspect(path string, fs afero.Fs)
}

// NewHunter creates an instance of the Hunter type
func NewHunter(c *Config) *Hunter {
	if c == nil {
		var config Config
		return &Hunter{config.Default(), NewHound(config.Default())}
	}
	if c.System == nil {
		log.Fatal("Missing filesystem in Hunter Config")
	}
	return &Hunter{c, NewHound(c)}
}

// Hunt walks over the filesystem at the configured path, looking for sensitive information
// it implements the Inspect method over an entire directory
func (h Hunter) Hunt() error {
	var files []string
	h.Hound = NewHound(h.Config)
	filter := afero.NewRegexpFs(h.Config.System, regexp.MustCompile(`(?i).*\.(json|y(am|m)l|toml|env|bash_history|(zsh|fish|bash)rc|ini)`))
	if err := afero.Walk(filter, h.Config.BasePath, func(path string, info os.FileInfo, err error) error {
		// Parse files for loot
		if info.IsDir() {
			return nil
		}

		files = append(files, path)
		return nil
	}); err != nil {
		return err
	}
	for _, f := range files {
		h.Inspect(f, h.Config.System)
	}
	return nil
}

// Inspect digs into the provided file and concurrently scans it for
// sensitive information
func (h Hunter) Inspect(path string, fs afero.Fs) {

	// Initialize channels and wait group
	jobs := make(chan string, 100)
	results := make(chan string)
	wg := new(sync.WaitGroup)

	// Initialize finding to hold results and count
	finding := Finding{
		Loot:    nil,
		Count:   0,
		Message: "",
		Path:    path,
	}

	// TODO handle the monochrome toggle in a more flexible way
	// Dig into the files matching the pattern
	f, err := fs.Open(path)
	if err != nil {
		panic(err)
	}

	defer f.Close()
	for w := 1; w <= runtime.NumCPU(); w++ {
		wg.Add(1)
		go h.matchPattern(jobs, results, wg)
	}

	// Scan the file for sensitive info matches
	go func() {
		s := bufio.NewScanner(f)
		for s.Scan() {
			jobs <- s.Text()
		}
		close(jobs)
	}()

	// Collect all the results
	go func() {
		wg.Wait()
		close(results)
	}()

	if h.Config.Verbose {
		finding.Message = fmt.Sprintf("[+] Scanning: %s", path)
	}

	var loot []string
	for v := range results {
		if v != "" {
			finding.Count += 1
			loot = append(loot, v)
		}
	}

	// Fill findings slice with results and print into
	// desired format
	if finding.Count > 0 {
		h.Hound.Findings = append(h.Hound.Findings, Finding{finding.Count, finding.Message, finding.Path, loot})
		h.Hound.Fetch()
	}
}

// matchPattern accepts a channel of jobs and looks for pattern matches
// in each of jobs
func (h *Hunter) matchPattern(jobs <-chan string, results chan<- string, wg *sync.WaitGroup) {
	// Mark task finished once done
	defer wg.Done()
	for j := range jobs {
		for _, r := range h.Config.Rules {
			if r.Regex.MatchString(j) {
				results <- r.Regex.FindString(j)
			}
		}
	}
}

// FilterResults sets the patterns to hunt for based on provided filters
func FilterResults(github bool, telephone bool, email bool) []*regexp.Regexp {
	if github {
		filtered := append([]*regexp.Regexp{}, reg.GitRepoRegex)
		return filtered
	}

	if telephone {
		filtered := append([]*regexp.Regexp{}, reg.PhonesWithExtsRegex)
		return filtered
	}

	if email {
		filtered := append([]*regexp.Regexp{}, reg.EmailRegex)
		return filtered
	}

	return DefaultPatterns
}
