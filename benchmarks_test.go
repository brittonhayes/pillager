package main_test

import (
	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/spf13/afero"
	"log"
	"os"
	"testing"
)

// A benchmark of the Hunter Load Rules method
func BenchmarkHunterLoadRules(b *testing.B) {
	for n := 0; n < b.N; n++ {
		hunter.LoadRules("")
	}
}

// A benchmark of the Hound Fetch method which
// prints results out in desired format
func BenchmarkHunterHoundFetch(b *testing.B) {
	b.StopTimer()
	h := hunter.NewHound(&hunter.Config{
		System: afero.NewMemMapFs(),
		Rules:  hunter.LoadRules(""),
		Format: hunter.JSONFormat,
	})
	h.Findings = []hunter.Finding{
		{
			Count:   1,
			Message: "Found something juicy",
			Path:    "example.toml",
			Loot:    []string{"Token 1234560"},
		},
	}

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		defer quiet()()
		h.Fetch()
	}
}

// A benchmark of the Hunter Inspect method
func BenchmarkHunterInspect(b *testing.B) {
	b.StopTimer()
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

	h := hunter.NewHunter(&hunter.Config{
		System:   fs,
		Rules:    hunter.LoadRules(""),
		BasePath: ".",
		Verbose:  true,
		Format:   hunter.JSONFormat,
	})

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		defer quiet()()
		h.Inspect(f.Name(), h.Config.System)
	}
}

func quiet() func() {
	null, _ := os.Open(os.DevNull)
	sout := os.Stdout
	serr := os.Stderr
	os.Stdout = null
	os.Stderr = null
	log.SetOutput(null)
	return func() {
		defer null.Close()
		os.Stdout = sout
		os.Stderr = serr
		log.SetOutput(os.Stderr)
	}
}
