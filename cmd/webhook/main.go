package main

import (
	"fmt"
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"go.rtnl.ai/acme-linode"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		fmt.Fprintln(os.Stderr, "GROUP_NAME environment variable is not set")
		os.Exit(1)
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&acme.LinodeDNSProviderSolver{},
	)
}
