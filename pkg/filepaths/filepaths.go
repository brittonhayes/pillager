package filepaths

import (
	"bufio"
	"fmt"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/gookit/color"
	"github.com/spf13/afero"
	"log"
	"os"
	"regexp"
)

var fileRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i).*\.(go|rtf|txt|js|php|java|json|xml|rb|md|markdown|\.db|database)`),
}

var contentRegexes = []*regexp.Regexp{
	regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"),
	regexp.MustCompile(`(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}`),
	regexp.MustCompile(`^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$`),
}

// WalkFn traverses the root path and checks for regex matches
func WalkFn(path string, os os.FileInfo, err error) error {
	var AppFs = afero.NewOsFs()

	// Setup new filesystem with only matches
	fs := afero.NewRegexpFs(AppFs, regexp.MustCompile(`(?i).*\.(go|rtf|txt|js|php|java|json|xml|rb|md|markdown|\.db|database)`))

	// Fill matches with file results
	files := FileHunter(path, fileRegexes)

	// Parse files for loot
	for _, f := range files {
		FileParser(f, fs)
	}

	return nil
}

func FileHunter(path string, patterns []*regexp.Regexp) []string {
	var matches []string
	for _, r := range patterns {
		err := validation.Validate(path,
			validation.Match(r),
		)
		if err == nil && path != "" {
			matches = append(matches, path)
		}
	}
	return matches
}

func FileParser(path string, fs afero.Fs) {

	foundLoot := false

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

	// Scan the file for sensitive info matches
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		for _, pattern := range contentRegexes {
			if pattern.MatchString(scanner.Text()) {
				foundLoot = true
				color.Green.Println("Loot:", scanner.Text())
			}
		}
	}

	if !foundLoot {
		color.Red.Println("Nothing found.")
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
