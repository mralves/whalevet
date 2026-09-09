package command

import (
	"os"
	"testing"

	"github.com/mralves/whalevet/internal/version"
)

func TestVersionPrintsInjectedVersion(t *testing.T) {
	old := version.Version
	version.Version = "v1.2.3"
	defer func() { version.Version = old }()

	// Capture stdout. RunVersion prints there and exits 0.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	RunVersion(nil)
	w.Close()
	os.Stdout = stdout

	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	if got := string(buf[:n]); got != "v1.2.3\n" {
		t.Errorf("version output = %q, want %q", got, "v1.2.3\n")
	}
}
