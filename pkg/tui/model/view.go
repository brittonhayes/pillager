package model

import (
	"fmt"
	"strings"

	"github.com/brittonhayes/pillager"
	"github.com/brittonhayes/pillager/pkg/tui/style"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	m.table, cmd = m.table.Update(msg)
	cmds = append(cmds, cmd)

	m.loading.spinner, cmd = m.loading.spinner.Update(msg)
	cmds = append(cmds, cmd)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.help.Width = msg.Width

	case resultsMsg:
		m.loading.active = false
		m.results = msg.results
		rows := addRowData(msg.results)
		m.table = m.table.WithRows(rows)
		return m, nil

	case errMsg:
		m.err = msg.err
		return m, nil

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keymap.Quit):
			return m, tea.Quit

		case key.Matches(msg, m.keymap.Inspect):
			m.body.selected.visible = !m.body.selected.visible
			return m, nil

		case key.Matches(msg, m.keymap.Help):
			m.help.ShowAll = !m.help.ShowAll
			return m, nil

		case key.Matches(msg, m.keymap.Start):
			m.loading.active = true
			return m, tea.Batch(startScan(m.scanner, m.scanner.ScanPath), m.loading.spinner.Tick)
		default:
			return m, m.loading.spinner.Tick
		}
	}

	return m, tea.Batch(cmds...)
}

func (m model) selectedView() string {
	if m.results != nil && m.body.selected.visible {
		w := &strings.Builder{}
		err := m.scanner.Reporter().Report(w, []pillager.Finding{m.selectedRow()})
		if err != nil {
			m.err = err
		}

		selected := style.Faint.Italic(true).Render(fmt.Sprintf("\nCurrent selection:\n%s", w.String()))
		return selected
	}
	return ""
}

func (m model) selectedRow() pillager.Finding {
	return m.results[m.table.HighlightedRow().Data[columnKeyID].(int)-1]
}

func (m model) View() string {
	if m.err != nil {
		return m.err.Error()
	}

	m.body.toast = ""
	if m.loading.active || m.loading.spinner.Visible() {
		m.body.message = fmt.Sprintf("%s Scanning for secrets in %q with %d workers", m.loading.spinner.View(), m.scanner.ScanPath, m.scanner.Workers)
	} else if m.results != nil {
		m.body.toast = style.Highlight.Render(fmt.Sprintf("Found %d secrets in path %q", len(m.results), m.scanner.ScanPath))
		m.body.message = m.table.View()
		m.body.message += m.selectedView()
	}

	title := style.Title.Render(m.header.title)
	subtitle := style.Subtitle.Render(m.header.subtitle)
	header := style.Header.Render(title + "\n" + subtitle)

	message := style.Text.Render(m.body.message)
	body := lipgloss.JoinVertical(lipgloss.Top, m.body.toast, message, m.body.selected.text)

	help := m.help.View(m.keymap)

	return lipgloss.JoinVertical(lipgloss.Top, header, body, help)
}
