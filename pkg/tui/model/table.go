package model

import (
	"path/filepath"
	"strings"

	"github.com/brittonhayes/pillager/pkg/tui/style"
	"github.com/evertras/bubble-table/table"
	"github.com/zricethezav/gitleaks/v8/report"
)

const (
	columnKeyID   = "id"
	columnWidthID = 4

	columnKeyFile   = "file"
	columnWidthFile = 20

	columnKeySecret   = "secret"
	columnWidthSecret = 35

	columnKeyRule   = "rule"
	columnWidthRule = 35
)

func newTable(width int) table.Model {
	// Create table model
	cols := []table.Column{
		table.NewColumn(columnKeyID, strings.ToTitle(columnKeyID), limit(columnWidthID, width)),
		table.NewColumn(columnKeyFile, strings.Title(columnKeyFile), limit(columnWidthFile, width)).WithFiltered(true),
		table.NewColumn(columnKeySecret, strings.Title(columnKeySecret), limit(columnWidthSecret, width)),
		table.NewColumn(columnKeyRule, strings.Title(columnKeyRule), limit(columnWidthRule, width)).WithFiltered(true),
	}
	t := table.New(cols).Focused(true).HighlightStyle(style.Highlight).WithPageSize(10)
	return t
}

func addRowData(data []report.Finding) []table.Row {
	rows := []table.Row{}

	for i, entry := range data {
		row := table.NewRow(table.RowData{
			columnKeyID:     i + 1,
			columnKeyFile:   filepath.Base(entry.File),
			columnKeySecret: entry.Secret,
			columnKeyRule:   entry.Description,
		})
		rows = append(rows, row)
	}

	return rows
}

func limit(w, max int) int {
	if w > max {
		return max
	}

	return w
}

func truncate(s string, width int) string {
	t := s
	if len(s) > width {
		if width > 3 {
			width -= 3
		}
		t = "..." + s[width:]
	}
	return t
}
