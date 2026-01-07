package acme_test

// import (
// 	"os"
// 	"testing"

// 	acmetest "github.com/cert-manager/cert-manager/test/acme"
// 	"go.rtnl.ai/acme-linode"
// )

// var (
// 	zone = os.Getenv("TEST_ZONE_NAME")
// )

// func TestRunsSuite(t *testing.T) {
// 	t.Skip("Skipping Linode DNS solver tests as they require external credentials and setup.")

// 	// The manifest path should contain a file named config.json that is a
// 	// snippet of valid configuration that should be included on the
// 	// ChallengeRequest passed as part of the test cases.

// 	solver := &acme.LinodeDNSProviderSolver{}
// 	fixture := acmetest.NewFixture(solver,
// 		acmetest.SetResolvedZone(zone),
// 		acmetest.SetAllowAmbientCredentials(false),
// 		acmetest.SetManifestPath("testdata/linode"),
// 		acmetest.SetUseAuthoritative(false),
// 	)

// 	//need to uncomment and  RunConformance delete runBasic and runExtended once https://github.com/cert-manager/cert-manager/pull/4835 is merged
// 	//fixture.RunConformance(t)
// 	fixture.RunBasic(t)
// 	fixture.RunExtended(t)
// }
