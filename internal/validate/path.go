package validate

import (
	"os"
)

// PathExists checks if a file at the given path exists and returns it if so,
// otherwise returns a default path.
func PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
