package component

import (
	"github.com/go-playground/validator/v10"
	"github.com/rivo/tview"
)

var validate *validator.Validate

type Component interface {
	View() *tview.Flex
	Validate() error
}
