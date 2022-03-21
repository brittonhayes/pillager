package model

import (
	"time"

	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/evertras/bubble-table/table"
	"github.com/zricethezav/gitleaks/v8/report"
)

const (
	columnKeyID     = "id"
	columnKeyFile   = "file"
	columnKeySecret = "secret"
	columnKeyRule   = "rule"
)

type model struct {
	keymap  keymap
	loading loading
	header  header
	body    body
	footer  footer
	table   table.Model

	hunter  *hunter.Hunter
	results []report.Finding
	err     error
}

type loading struct {
	active  bool
	spinner spinner.Model
}

type header struct {
	title    string
	subtitle string
}

type body struct {
	toast   string
	message string
}

type footer struct {
	help help.Model
}

type resultsMsg struct{ results []report.Finding }

type errMsg struct{ err error }

// For messages that contain errors it's often handy to also implement the
// error interface on the message.
func (e errMsg) Error() string { return e.err.Error() }

func NewModel(hunt *hunter.Hunter) model {
	// Create table model
	t := newTable()
	// Create keymap
	k := newKeyMap()
	// Create loading spinner.
	s := newSpinner()
	// Create help model
	h := help.New()

	return model{
		hunter: hunt,
		header: header{
			title:    "Pillager",
			subtitle: "Hunt inside the file system for valuable information",
		},
		table: t,
		body: body{
			message: "",
		},
		footer: footer{
			help: h,
		},
		loading: loading{
			active:  false,
			spinner: s,
		},
		keymap: k,
	}
}

func startScan(h *hunter.Hunter) tea.Cmd {
	return func() tea.Msg {
		h.Debug = false
		h.Verbose = false
		time.Sleep(2 * time.Second)
		results, err := h.Hunt()
		if err != nil {
			// There was an error making our request. Wrap the error we received
			// in a message and return it.
			return errMsg{err}
		}

		return resultsMsg{results}
	}
}
