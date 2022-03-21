package model

import (
	"fmt"
	"os"

	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/brittonhayes/pillager/pkg/tui/style"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/evertras/bubble-table/table"
	"github.com/zricethezav/gitleaks/v8/report"
	"golang.org/x/term"
)

type model struct {
	keymap  keymap
	loading loading
	header  header
	body    body
	help    help.Model
	table   table.Model

	hunter  *hunter.Hunter
	results []report.Finding
	err     error

	width  int
	height int
}

type loading struct {
	active  bool
	spinner spinner.Model
}

type header struct {
	title    string
	subtitle string
}

type selected struct {
	visible bool
	text    string
}

type body struct {
	toast    string
	selected selected
	message  string
}

type resultsMsg struct{ results []report.Finding }

type errMsg struct{ err error }

func (e errMsg) Error() string {
	return fmt.Sprintf("🔥 Uh oh! Well that's not good. Looks like something went wrong and the application has exited: \n\n%s\n\n%s", style.Error.Render(e.Error()), "Press [q] to quit.")
}

func NewModel(hunt *hunter.Hunter) model {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width = 80
		height = 24
	}

	// Create table model
	t := newTable(width)
	// Create keymap
	k := newKeyMap()
	// Create loading spinner.
	s := newSpinner()
	// Create help model
	h := help.New()

	m := model{
		hunter: hunt,
		header: header{
			title:    "Pillager",
			subtitle: "Hunt inside the file system for valuable information",
		},
		table: t,
		body: body{
			message: "",
		},
		help: h,
		loading: loading{
			active:  false,
			spinner: s,
		},
		keymap: k,
		width:  width,
		height: height,
	}

	return m
}

func (m model) Dimensions() (int, int) {
	return m.width, m.height
}

func startScan(h *hunter.Hunter) tea.Cmd {
	return func() tea.Msg {
		h.Debug = false
		h.Verbose = false
		results, err := h.Hunt()
		if err != nil {
			// There was an error making our request. Wrap the error we received
			// in a message and return it.
			return errMsg{err}
		}

		return resultsMsg{results}
	}
}
