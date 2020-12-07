package hunter

import (
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"regexp"
)

// This is an example of how to run a scan on a single file to look for
// email addresses. We're using an in-memory file system for simplicity,
// but this supports using an actual file system as well.
func ExampleHunter_Inspect_email() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("example.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(`example@email.com`))
	if err != nil {
		panic(err)
	}

	c := Config{
		System:     fs,
		Patterns:   []*regexp.Regexp{reg.EmailRegex},
		BasePath:   CheckPath(fs, "."),
		Monochrome: false,
		Verbose:    true,
		Format:     StringToFormat("yaml"),
	}
	h := NewHunter(&c)
	h.Inspect(f.Name(), h.Config.System)
	// output:
	// - count: 1
	//   loot:
	//   - example@email.com
	//   message: '[+] Scanning: example.txt'
	//   path: example.txt
}

// This method also accepts custom output formats using
// go template/html. So if you don't like yaml or json,
// you can format to your heart's content.
func ExampleHunter_Inspect_custom_output() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("example.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(`https://github.com/brittonhayes/pillager`))
	if err != nil {
		panic(err)
	}

	c := Config{
		System:     fs,
		Patterns:   FilterResults(false, false, false, false, false),
		BasePath:   CheckPath(fs, "."),
		Monochrome: false,
		Verbose:    true,
		Format:     StringToFormat("custom"),
	}
	h := NewHunter(&c)
	h.Inspect(f.Name(), h.Config.System)
}

// This method accepts json output format
// as well
func ExampleHunter_Inspect_json() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("fake.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(`git@github.com:brittonhayes/pillager.git`))
	if err != nil {
		panic(err)
	}

	c := Config{
		System:     fs,
		Patterns:   FilterResults(false, false, false, false, false),
		BasePath:   CheckPath(fs, "."),
		Monochrome: false,
		Verbose:    true,
		Format:     StringToFormat("json"),
	}
	h := NewHunter(&c)
	h.Inspect(f.Name(), h.Config.System)
	// output:
	// [{"count":2,"message":"[+] Scanning: fake.txt","path":"fake.txt","loot":["git@github.com:brittonhayes/pillager.git","git@github.com"]}]
}
