package model

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
)

type keymap struct {
	Filter  key.Binding
	Inspect key.Binding
	Start   key.Binding
	Quit    key.Binding
	Help    key.Binding
}

func newKeyMap() keymap {
	k := keymap{
		Inspect: key.NewBinding(
			key.WithKeys("i"),
			key.WithHelp("i", "inspect"),
		),
		Filter: key.NewBinding(
			key.WithKeys("f"),
			key.WithHelp("f", "filter"),
		),
		Start: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "scan"),
		),
		Quit: key.NewBinding(
			key.WithKeys("ctrl+c", "q"),
			key.WithHelp("ctrl+c/q", "quit"),
		),
		Help: key.NewBinding(
			key.WithKeys("?"),
			key.WithHelp("?", "help"),
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
		{k.Help, k.Start, k.Inspect, k.Quit},
		{k.Quit, k.Filter},
	}
}

// ShortHelp returns keybindings for the short help view.
func (k keymap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Start, k.Inspect, k.Quit}
}
