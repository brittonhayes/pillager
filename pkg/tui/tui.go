package tui

import (
	"log"
	"os"

	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/brittonhayes/pillager/pkg/tui/component"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// theme holds the color theme for the tview TUI.
var theme = tview.Theme{
	PrimitiveBackgroundColor:    tcell.Color(272727),
	ContrastBackgroundColor:     tcell.Color(448488),
	MoreContrastBackgroundColor: tcell.ColorGreen,
	BorderColor:                 tcell.ColorWhite,
	TitleColor:                  tcell.ColorWhite,
	GraphicsColor:               tcell.ColorWhite,
	PrimaryTextColor:            tcell.ColorWhite,
	SecondaryTextColor:          tcell.ColorYellow,
	TertiaryTextColor:           tcell.ColorGreen,
	InverseTextColor:            tcell.Color(448488),
	ContrastSecondaryTextColor:  tcell.ColorDarkCyan,
}

func Run(h *hunter.Hunter) error {
	app := tview.NewApplication()
	tview.Styles = theme

	configView := component.NewConfig(h).View()
	outputView := component.NewOutput().View()

	content := tview.NewFlex().
		AddItem(configView, 0, 1, true).
		AddItem(outputView, 0, 2, false)

	content.SetBorder(true).
		SetTitle(" pillager ").
		SetBorderPadding(1, 1, 1, 1)

	label := "Enter Scan Path: "
	input := component.NewInput(label, func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}

		findings, err := h.Hunt()
		if err != nil {
			log.Printf("\n\n%v", err)
		}

		table := component.NewTable(findings).View()
		outputView.Clear().AddItem(table, 0, 1, false)
	}).View()

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(content, 0, 3, false).
		AddItem(input, 0, 1, false)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'i':
			app.SetFocus(input)
		case 'c':
			app.SetFocus(content)
		case 'q':
			app.Stop()
			os.Exit(0)
		}

		return event
	})

	return app.SetRoot(flex, true).SetFocus(input).EnableMouse(true).Run()
}
