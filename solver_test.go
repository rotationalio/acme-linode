package acme_test

import (
	"os"
	"testing"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	"go.rtnl.ai/acme-linode"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	if zone == "" {
		t.Skip("Skipping Linode DNS provider solver tests as TEST_ZONE_NAME environment variable is not set")
	}

	if !secretExists() {
		t.Skip("Skipping Linode DNS provider solver tests as Linode API credentials secret not found")
	}

	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	solver := &acme.LinodeDNSProviderSolver{}
	fixture := acmetest.NewFixture(solver,
		acmetest.SetResolvedZone(zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath("testdata/linode"),
		acmetest.SetUseAuthoritative(false),
	)

	// Removed RunBasic then RunExtended before https://github.com/cert-manager/cert-manager/pull/4835 is merged
	// because I was getting a panic when running them both in the same test suite.
	// This method seems to pass the tests just fine.
	fixture.RunConformance(t)
}

func secretExists() bool {
	_, err := os.Stat("testdata/linode/secret.yaml")
	return err == nil
}
