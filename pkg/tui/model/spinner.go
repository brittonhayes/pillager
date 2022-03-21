package model

import (
	"time"

	"github.com/brittonhayes/pillager/pkg/tui/style"
	"github.com/charmbracelet/bubbles/spinner"
)

func newSpinner() spinner.Model {
	// Create loading spinner.
	s := spinner.NewModel()
	s.Spinner = spinner.Dot
	s.Style = style.Spinner
	s.HideFor = 250 * time.Millisecond
	return s
}
