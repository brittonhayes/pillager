package model

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

type keymap struct {
	filter key.Binding
	start  key.Binding
	quit   key.Binding
}

func newKeyMap() keymap {
	k := keymap{
		filter: key.NewBinding(
			key.WithKeys(tea.KeyCtrlI.String()),
			key.WithHelp("ctrl+i", "filter"),
		),
		start: key.NewBinding(
			key.WithKeys(tea.KeyEnter.String()),
			key.WithHelp("enter", "start"),
		),
		quit: key.NewBinding(
			key.WithKeys("q", "ctrl+c"),
			key.WithHelp("q", "quit"),
		),
	}

	// Assert complies with help interface
	var _ help.KeyMap = k

	return k
}

// FullHelp returns keybindings for the expanded help view. It's part of the
// key.Map interface.
func (k keymap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.start, k.quit},
		{k.filter},
	}
}

// ShortHelp returns keybindings for the short help view.
func (k keymap) ShortHelp() []key.Binding {
	return []key.Binding{k.start, k.quit}
}
