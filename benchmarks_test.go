package main_test

import (
	"log"
	"os"
	"testing"

	"github.com/brittonhayes/pillager/hunter"
	"github.com/brittonhayes/pillager/rules"
	"github.com/spf13/afero"
	"github.com/zricethezav/gitleaks/v7/scan"
)

// A benchmark of the Hunter Load Rules method
func BenchmarkHunterLoadRules(b *testing.B) {
	for n := 0; n < b.N; n++ {
		rules.Load("")
	}
}

// A benchmark of the Hound Howl method which
// prints results out in desired format
func BenchmarkHunterHoundHowl(b *testing.B) {
	b.StopTimer()
	h := hunter.NewHound(&hunter.Config{
		System:   afero.NewMemMapFs(),
		Gitleaks: rules.Load(""),
		Format:   hunter.JSONFormat,
	})
	findings := scan.Report{
		Leaks: []scan.Leak{
			{Line: "person@email.com", LineNumber: 16, Offender: "person@email.com", Rule: "Email Addresses"},
		},
	}

	b.StartTimer()
	for n := 0; n < b.N; n++ {
		defer quiet()()
		h.Howl(findings)
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
