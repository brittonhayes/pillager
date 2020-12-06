package hunter

import (
	"github.com/spf13/afero"
	"log"
	"os"
)

func (h Hunter) CheckPath(fs afero.Fs, path string) string {
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
