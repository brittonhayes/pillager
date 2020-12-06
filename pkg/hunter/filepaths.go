package hunter

import (
	"bufio"
	"fmt"
	"github.com/gookit/color"
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"os"
	"regexp"
	"sync"
)

type Hunter struct {
	System   afero.Fs
	Patterns []*regexp.Regexp
	BasePath string
}

var _ Hunting = Hunter{}

type Hunting interface {
	Hunt() error
	inspect(path string, fs afero.Fs)
}

var contentRegexes = []*regexp.Regexp{
	reg.CreditCardRegex,
	reg.VISACreditCardRegex,
	reg.GitRepoRegex,
}

// NewHunter creates an instance of the Hunter type
func NewHunter(system afero.Fs, patterns []*regexp.Regexp, location string) *Hunter {
	return &Hunter{System: system, Patterns: patterns, BasePath: location}
}

func (h Hunter) Hunt() error {
	var files []string
	filter := afero.NewRegexpFs(h.System, regexp.MustCompile(`(?i).*\.(go|rtf|txt|csv|js|php|java|json|xml|rb|md|markdown)`))
	if err := afero.Walk(filter, h.BasePath, func(path string, info os.FileInfo, err error) error {
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
		h.inspect(f, h.System)
	}

	return nil
}

func (h Hunter) inspect(path string, fs afero.Fs) {
	//foundLoot := false
	// Print file found message
	plus := color.Bold.Text("[+]")
	hit := color.Cyan.Text("Scanning: ")
	message := fmt.Sprintf("%s %s %s", plus, hit, path)
	fmt.Println(message)
	// Dig into the files matching the pattern
	f, err := fs.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Initialize channels and wait group
	jobs := make(chan string)
	results := make(chan string)
	wg := new(sync.WaitGroup)

	for w := 1; w <= 3; w++ {
		wg.Add(1)
		go matchPattern(jobs, results, wg, []*regexp.Regexp{
			reg.CreditCardRegex,
			reg.BtcAddressRegex,
			reg.VISACreditCardRegex,
			reg.GitRepoRegex,
		})
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

	total := 0
	for v := range results {
		total += 1
		color.Cyan.Println("Loot:", v)
	}

	if total >= 1 {
		color.Bold.Println("TOTAL:\t", total)
	} else {
		color.Red.Println("Nothing found")
	}
}

func matchPattern(jobs <-chan string, results chan<- string, wg *sync.WaitGroup, pattern []*regexp.Regexp) {
	// Mark task finished once done
	defer wg.Done()
	for j := range jobs {
		for _, p := range pattern {
			if p.MatchString(j) {
				results <- j
			}
		}
	}
}
