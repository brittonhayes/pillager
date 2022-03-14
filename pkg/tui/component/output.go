package component

import (
	"log"

	"github.com/go-playground/validator/v10"
	"github.com/rivo/tview"
)

type Output struct {
	text string
}

func NewOutput(text string) *Output {
	return &Output{
		text: text,
	}
}

func (o *Output) View() *tview.Flex {
	if err := o.Validate(); err != nil {
		log.Fatal(err)
	}

	body := tview.NewTextView().SetScrollable(true).SetTextAlign(tview.AlignLeft).SetText(o.text)
	body.SetBorder(true).SetBorderPadding(0, 1, 1, 1)

	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, false)

	return flex
}

func (o *Output) Validate() error {
	validate = validator.New()
	return validate.Struct(o)
}
