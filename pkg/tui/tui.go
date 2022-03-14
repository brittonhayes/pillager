package tui

import (
	"bytes"
	"fmt"
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
	outputView := component.NewOutput("press enter to search").View()

	container := tview.NewFlex()
	container.SetBorder(true).
		SetTitle(fmt.Sprintf(" %s ", "pillager")).
		SetBorderPadding(1, 1, 1, 1)

	container.AddItem(configView, 0, 1, false).AddItem(outputView, 0, 2, false)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(container, 0, 3, true)

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEnter:

			findings, err := h.Hunt()
			if err != nil {
				log.Printf("\n\n%v", err)
			}

			buf := bytes.NewBuffer(nil)
			if err := h.Report(buf, findings); err != nil {
				log.Printf("\n\n%v", err)
			}

			outputView.Clear().AddItem(component.NewOutput(buf.String()).View(), 0, 2, false)

		case tcell.KeyClear:
			app.Stop()
			os.Exit(0)

		default:
			return event
		}

		return event
	})

	return app.SetRoot(flex, true).EnableMouse(true).Run()
}
