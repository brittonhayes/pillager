package model

import (
	"fmt"
	"time"

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

	case resultsMsg:
		m.loading.active = false
		m.results = msg.results
		rows := addRowData(msg.results)
		m.table = m.table.WithRows(rows)
		return m, nil

	case errMsg:
		// There was an error. Note it in the model. And tell the runtime
		// we're done and want to quit.
		m.err = msg.err
		time.Sleep(3 * time.Second)
		return m, tea.Quit

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keymap.quit):
			return m, tea.Quit

		case key.Matches(msg, m.keymap.filter):
			m.table = m.table.StartFilterTyping()
			return m, nil

		case key.Matches(msg, m.keymap.start):
			m.loading.active = true
			return m, tea.Batch(startScan(m.hunter), m.loading.spinner.Tick)
		default:
			return m, m.loading.spinner.Tick
		}
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	// If there's an error, print it out and don't do anything else.
	if m.err != nil {
		return style.Error.Render(fmt.Sprintf("\n Uh oh! Something went\n%s\n\n", m.err))
	}

	m.body.toast = ""
	if m.loading.active || m.loading.spinner.Visible() {
		m.body.message = fmt.Sprintf("Scanning for secrets in %q with %d workers %s", m.hunter.ScanPath, m.hunter.Workers, m.loading.spinner.View())
	} else if m.results != nil {

		m.body.toast = style.Highlight.Render(fmt.Sprintf("Found %d secrets in path %q", len(m.results), m.hunter.ScanPath))
		m.body.message = m.table.View()
	}

	title := style.Title.Render(m.header.title)
	subtitle := style.Subtitle.Render(m.header.subtitle)
	header := style.Header.Render(title + "\n" + subtitle)

	message := style.Text.Render(m.body.message)
	body := lipgloss.JoinVertical(lipgloss.Top, m.body.toast, message)

	help := style.Faint.MarginTop(2).Render(m.footer.help.View(m.keymap))
	footer := lipgloss.JoinVertical(lipgloss.Top, help)

	return lipgloss.JoinVertical(lipgloss.Top, header, body, footer)
}
