package hunter

import (
	"github.com/spf13/afero"
)

// This is an example of how to run a scan on a single file to look for
// email addresses. We're using an in-memory file system for simplicity,
// but this supports using an actual file system as well.
func ExampleHunter_Inspect_email() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("example.toml")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(`example@email.com`))
	if err != nil {
		panic(err)
	}

	c := Config{
		System:   fs,
		BasePath: CheckPath(fs, "."),
		Verbose:  true,
		Format:   StringToFormat("yaml"),
		Rules:    LoadRules(""),
	}
	h := NewHunter(&c)
	h.Inspect(f.Name(), h.Config.System)
	// output:
	// - count: 1
	//   loot:
	//   - example@email.com
	//   message: '[+] Scanning: example.toml'
	//   path: example.toml
}

// This method also accepts custom output formats using
// go template/html. So if you don't like yaml or json,
// you can format to your heart's content.
func ExampleHunter_Inspect_custom_output() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("example.yaml")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	_, err = f.Write([]byte(`https://github.com/brittonhayes/pillager`))
	if err != nil {
		panic(err)
	}

	c := Config{
		System:   fs,
		BasePath: ".",
		Verbose:  true,
		Format:   CustomFormat,
	}
	h := NewHunter(&c)
	h.Inspect(f.Name(), h.Config.System)
}

// This method accepts json output format
// as well
func ExampleHunter_Inspect_json() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("fake.json")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = f.Write([]byte(`git@github.com:brittonhayes/pillager.git`))
	if err != nil {
		panic(err)
	}

	h := NewHunter(&Config{
		System:   fs,
		BasePath: ".",
		Verbose:  true,
		Format:   JSONFormat,
		Rules:    LoadRules(""),
	})
	h.Inspect(f.Name(), h.Config.System)
	// output:
	// [{"count":2,"message":"[+] Scanning: fake.json","path":"fake.json","loot":["git@github.com","git@github.com:brittonhayes/pillager.git"]}]
}

// Hunter will also look personally identifiable info in TOML
func ExampleHunter_Inspect_toml() {
	fs := afero.NewMemMapFs()
	f, err := fs.Create("fake.toml")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = f.Write([]byte(`fakeperson@example.com`))
	if err != nil {
		panic(err)
	}

	h := NewHunter(&Config{
		System:   fs,
		Rules:    LoadRules(""),
		BasePath: CheckPath(fs, "."),
		Verbose:  true,
		Format:   JSONFormat,
	})
	h.Inspect(f.Name(), h.Config.System)
	// output:
	// [{"count":1,"message":"[+] Scanning: fake.toml","path":"fake.toml","loot":["fakeperson@example.com"]}]
}
