package cmdutil

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// captureStdout calls fn while capturing everything written to os.Stdout,
// then returns the captured output as a string.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	w.Close()
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	os.Stdout = old

	return buf.String()
}
