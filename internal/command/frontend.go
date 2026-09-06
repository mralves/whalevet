package command

import (
	"fmt"
	"os"

	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	_ "github.com/moby/buildkit/util/grpcutil/encoding/proto"
	"github.com/mralves/whalevet/internal/frontend"
)

// RunFrontend is the BuildKit gateway entrypoint used by the wrapper image:
//
//	ENTRYPOINT ["/whalevet", "frontend"]
//
// It is intentionally not shown in usage().
func RunFrontend(args []string) {
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Printf("%s whalevet\n", os.Args[0])
		return
	}
	if err := grpcclient.RunFromEnvironment(appcontext.Context(), frontend.Build); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
