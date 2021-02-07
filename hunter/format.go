package hunter

import "strings"

const (
	JSONFormat Format = iota + 1
	YAMLFormat
	CustomFormat
)

type Format int

func (f Format) String() string {
	return [...]string{"json", "yaml", "custom"}[f]
}

// StringToFormat takes in a string representation of the preferred
// output format and returns to enum equivalent
func StringToFormat(s string) Format {
	switch strings.ToLower(s) {
	case "yaml":
		return YAMLFormat
	case "custom":
		return CustomFormat
	default:
		return JSONFormat
	}
}
