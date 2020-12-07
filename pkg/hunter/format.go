package hunter

const (
	JSONFormat Format = iota + 1
	YAMLFormat
	CustomFormat
)

type Format int

func (f Format) String() string {
	return [...]string{"json", "yaml", "custom"}[f]
}
