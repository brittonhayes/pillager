package hunter

import (
	"github.com/spf13/afero"
	"log"
	"os"
)

// CheckPath checks if a filepath exists and
// returns it if so, otherwise returns a default path
func CheckPath(fs afero.Fs, path string) string {
	ok, err := afero.Exists(fs, path)
	if err != nil {
		log.Printf("ERROR: %s", err.Error())
		os.Exit(1)
	}

	if ok {
		return path
	}

	log.Printf("INFO: %s", "no valid path provided, using current directory")
	return "."
}
