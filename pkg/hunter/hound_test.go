package hunter

import (
	reg "github.com/mingrammer/commonregex"
	"github.com/spf13/afero"
	"regexp"
)

// Here is an example of utilizing the Howl function
// on a slice of findings. The Howl method is the final
// method in the hunting process. It takes whatever
// has been found and outputs it for the user.
func ExampleHound_Howl_json() {
	h := NewHound(&Config{
		System:   afero.NewMemMapFs(),
		Patterns: []*regexp.Regexp{reg.EmailRegex},
		Format:   JSONFormat,
	})
	f := []Finding{
		{
			Count:   1,
			Message: "Found something juicy",
			Path:    "example.txt",
			Loot:    []string{"1234560"},
		},
	}
	h.Howl(f)
	// output:
	// [{"count":1,"message":"Found something juicy","path":"example.txt","loot":["1234560"]}]
}
