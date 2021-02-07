package hunter

import (
	"github.com/brittonhayes/pillager/rules"
	"github.com/spf13/afero"
)

// This is an example of how to run a scan on a single file to look for
// email addresses. We're using an in-memory file system for simplicity,
// but this supports using an actual file system as well.
func ExampleHunter_Hunt_email() {
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

	config := NewConfig(fs, "./", true, rules.Load(""), StringToFormat("yaml"), DefaultTemplate, 5)
	h := NewHunter(config)
	_ = h.Hunt()
}

// This method also accepts custom output formats using
// go template/html. So if you don't like yaml or json,
// you can format to your heart's content.
func ExampleHunter_Hunt_custom_output() {
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

	config := NewConfig(fs, "./", true, rules.Load(""), CustomFormat, DefaultTemplate, 5)
	h := NewHunter(config)
	_ = h.Hunt()
}

// This method accepts json output format
// as well
func ExampleHunter_Hunt_json() {
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

	config := NewConfig(fs, ".", true, rules.Load(""), JSONFormat, DefaultTemplate, 5)
	h := NewHunter(config)
	_ = h.Hunt()
}

// Hunter will also look personally identifiable info in TOML
func ExampleHunter_Hunt_toml() {
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

	config := NewConfig(fs, ".", true, rules.Load(""), JSONFormat, DefaultTemplate, 5)

	h := NewHunter(config)
	_ = h.Hunt()
}
