package model

import (
	"strings"

	"github.com/brittonhayes/pillager/pkg/tui/style"
	"github.com/evertras/bubble-table/table"
	"github.com/zricethezav/gitleaks/v8/report"
)

func newTable() table.Model {
	// Create table model
	t := table.New([]table.Column{
		table.NewColumn(columnKeyID, strings.ToTitle(columnKeyID), 4),
		table.NewColumn(columnKeyFile, strings.Title(columnKeyFile), 40),
		table.NewColumn(columnKeySecret, strings.Title(columnKeySecret), 30),
		table.NewColumn(columnKeyRule, strings.Title(columnKeyRule), 35),
	}).WithPageSize(10).Focused(true).HighlightStyle(style.Highlight)
	return t
}

func addRowData(data []report.Finding) []table.Row {
	rows := []table.Row{}

	for i, entry := range data {
		row := table.NewRow(table.RowData{
			columnKeyID:     i + 1,
			columnKeyFile:   entry.File,
			columnKeySecret: entry.Secret,
			columnKeyRule:   entry.Description,
		})

		rows = append(rows, row)
	}

	return rows
}
