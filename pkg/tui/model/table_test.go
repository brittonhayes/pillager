package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTruncate(t *testing.T) {
	t.Run("truncates string", func(t *testing.T) {
		arg := "foobarbaz"
		want := "...barbaz"
		got := truncate(arg, 3)

		assert.Equal(t, want, got)
	})

	t.Run("truncates filepath", func(t *testing.T) {
		arg := "C:/Users/foo/bar/baz/qux/quux.go"
		want := "...Users/foo/bar/baz/qux/quux.go"
		got := truncate(arg, 6)

		assert.Equal(t, want, got)
	})
}
