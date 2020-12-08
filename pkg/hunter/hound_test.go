package hunter

import (
	"github.com/spf13/afero"
)

// Here is an example of utilizing the Howl function
// on a slice of findings. The Howl method is the final
// method in the hunting process. It takes whatever
// has been found and outputs it for the user.
func ExampleHound_Fetch_json() {
	h := NewHound(&Config{
		System: afero.NewMemMapFs(),
		Rules:  LoadRules(""),
		Format: JSONFormat,
	})
	h.Findings = []Finding{
		{
			Count:   1,
			Message: "Found something juicy",
			Path:    "example.toml",
			Loot:    []string{"Token 1234560"},
		},
	}
	h.Fetch()
	// output:
	// [{"count":1,"message":"Found something juicy","path":"example.toml","loot":["Token 1234560"]}]
}
