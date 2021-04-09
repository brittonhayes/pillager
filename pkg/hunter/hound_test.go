package hunter

import (
	rules2 "github.com/brittonhayes/pillager/pkg/rules"
	"github.com/spf13/afero"
	"github.com/zricethezav/gitleaks/v7/scan"
)

// Here is an example of utilizing the Howl function
// on a slice of findings. The Howl method is the final
// method in the hunting process. It takes whatever
// has been found and outputs it for the user.
func ExampleHound_Howl_json() {
	h := NewHound(&Config{
		System:   afero.NewMemMapFs(),
		Gitleaks: rules2.Load(""),
		Format:   JSONFormat,
	})
	findings := scan.Report{
		Leaks: []scan.Leak{
			{Line: "person@email.com", LineNumber: 16, Offender: "person@email.com", Rule: "Email Addresses"},
		},
	}

	h.Howl(findings)
}
