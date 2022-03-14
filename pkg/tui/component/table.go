package component

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Table struct {
	findings []report.Finding
}

func NewTable(rows []report.Finding) *Table {
	return &Table{
		findings: rows,
	}
}

func (t *Table) View() tview.Primitive {
	if len(t.findings) == 0 {
		return tview.NewTextView().SetText("No results")
	}

	table := tview.NewTable().
		SetBorders(true)

	columns := []string{
		"FILE",
		"TYPE",
		"SECRET",
	}

	for index, column := range columns {
		table.SetCell(0, index,
			tview.NewTableCell(column).
				SetTextColor(tcell.ColorLightCyan).
				SetAlign(tview.AlignCenter))
	}

	for i := 0; i < len(t.findings); i++ {
		table.SetCell(i+1, 0,
			tview.NewTableCell(t.findings[i].File).
				SetTextColor(tcell.ColorLightCyan).
				SetAlign(tview.AlignCenter))

		table.SetCell(i+1, 1,
			tview.NewTableCell(t.findings[i].Description).
				SetTextColor(tcell.ColorLightCyan).
				SetAlign(tview.AlignCenter))

		table.SetCell(i+1, 2,
			tview.NewTableCell(t.findings[i].Secret).
				SetTextColor(tcell.ColorLightCyan).
				SetAlign(tview.AlignCenter))
	}

	return table
}
