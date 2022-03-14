package component

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/brittonhayes/pillager/pkg/hunter"
	"github.com/gdamore/tcell/v2"
	"github.com/go-playground/validator/v10"
	"github.com/rivo/tview"
)

type Config struct {
	title  string `validate:"required"`
	hunter *hunter.Hunter
}

func NewConfig(h *hunter.Hunter) *Config {
	return &Config{
		title:  " Current Config ",
		hunter: h,
	}
}

func (c *Config) View() *tview.Flex {
	if err := c.Validate(); err != nil {
		log.Fatal(err)
	}

	aboutFlex := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(tview.NewTextView().SetText(BannerText).SetTextAlign(tview.AlignCenter), 0, 1, false)

	currentFlex := c.currentConfigView()
	aboutFlex.SetBorder(false).SetBorderPadding(1, 1, 1, 1)
	currentFlex.SetBorder(false).SetTitle(c.title).SetBorderPadding(0, 0, 1, 1)

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(aboutFlex, 0, 1, false).
		AddItem(currentFlex, 0, 2, false)
	return flex
}

func (c *Config) Validate() error {
	validate = validator.New()
	return validate.Struct(c)
}

func (c *Config) currentConfigView() *tview.Flex {
	absScanPath, err := filepath.Abs(c.hunter.ScanPath)
	if err != nil {
		absScanPath = c.hunter.ScanPath
	}

	rulesText := c.hunter.Gitleaks.Description
	if c.hunter.Gitleaks.Description == "" {
		rulesText = "No description found in gitleaks configuration"
	}

	flex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(c.newItem("ScanPath", absScanPath), 0, 1, false).
		AddItem(c.newItem("Rules", rulesText), 0, 1, false).
		AddItem(c.newItem("Format", fmt.Sprintf("%T", c.hunter.Reporter)[7:]), 3, 0, false).
		AddItem(c.newItem("NumWorkers", fmt.Sprintf("%d", c.hunter.Workers)), 3, 0, false).
		AddItem(c.newItem("Verbose", fmt.Sprintf("%v", c.hunter.Verbose)), 3, 0, false).
		AddItem(c.newItem("Redact", fmt.Sprintf("%v", c.hunter.Redact)), 3, 0, false)

	return flex
}

func (c *Config) newItem(title, text string) *tview.Form {
	t := tview.NewForm()

	t.AddInputField("", text, 0, nil, nil)

	t.SetBorder(true).
		SetBorderPadding(0, 0, 1, 1).
		SetTitle(fmt.Sprintf(" %s ", title)).
		SetTitleAlign(0).
		SetTitleColor(tcell.ColorGray)
	return t
}
