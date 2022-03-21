package style

import (
	"github.com/brittonhayes/glitter/theme"
	"github.com/charmbracelet/lipgloss"
)

var (
	styleBase = lipgloss.NewStyle().Align(lipgloss.Left).Foreground(theme.Nord.Primary.Foreground)

	Header = lipgloss.NewStyle().Padding(1, 0).Align(lipgloss.Left)

	Title    = styleBase.Copy().Bold(true).Foreground(theme.Nord.Normal.Cyan)
	Subtitle = Title.Copy().Bold(false).Italic(true).Foreground(theme.Nord.Primary.Foreground)

	Text      = styleBase.Copy().Padding(0).Bold(false)
	Error     = styleBase.Copy().MarginLeft(2).Foreground(theme.Nord.Normal.Yellow)
	Faint     = styleBase.Copy().Foreground(theme.Nord.Primary.DimForeground).Faint(true)
	Spinner   = styleBase.Copy().Foreground(theme.Nord.Bright.Cyan)
	Highlight = lipgloss.NewStyle().Foreground(theme.Nord.Normal.Cyan)
	Accent    = lipgloss.NewStyle().Foreground(theme.Nord.Bright.Magenta)
)
