package command

import (
	"fmt"
	"os"

	"github.com/mralves/whalevet/internal/version"
)

// RunVersion prints the whalevet version to stdout and exits 0.
func RunVersion(args []string) {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: whalevet version")
		os.Exit(2)
	}
	fmt.Println(version.Version)
}