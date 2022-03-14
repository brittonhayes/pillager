package component

import (
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/rivo/tview"
)

type Output struct{}

func NewOutput() *Output {
	return &Output{}
}

func (o *Output) View() *tview.Flex {
	if err := o.Validate(); err != nil {
		log.Fatal(err)
	}

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetTextAlign(tview.AlignCenter), 0, 1, false)

	return flex
}

func (o *Output) Validate() error {
	validate = validator.New()
	return validate.Struct(o)
}
