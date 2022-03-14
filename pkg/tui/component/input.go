package component

import (
	"log"

	"github.com/gdamore/tcell/v2"
	"github.com/go-playground/validator/v10"
	"github.com/rivo/tview"
)

type Input struct {
	handler func(key tcell.Key) `validate:"required"`
	label   string              `validate:"required"`
	title   string              `validate:"required"`
}

func NewInput(label string, handler func(key tcell.Key)) *Input {
	return &Input{
		title:   " scan path ",
		label:   label,
		handler: handler,
	}
}

func (i *Input) View() *tview.Flex {
	if err := i.Validate(); err != nil {
		log.Fatal(err)
	}

	inputField := tview.NewInputField().
		SetLabel(i.label).
		SetDoneFunc(i.handler).
		SetFieldWidth(0)

	flex := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(inputField, 0, 1, true)
	flex.SetBorder(true).SetTitle(i.title).SetBorderPadding(0, 1, 1, 1)

	return flex
}

func (i *Input) Validate() error {
	validate = validator.New()
	return validate.Struct(i)
}
