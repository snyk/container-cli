package test

import (
	_ "embed"
	containercli "github.com/snyk/container-cli/pkg"
	"strings"
	"testing"

	sbomtest "github.com/snyk/cli-extension-sbom/test"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

var (
	//go:embed testdata/container_scan_output.txt
	containerScanOutput []byte
	//go:embed testdata/container_scan_depgraph.json
	containerDepGraph []byte
)

func TestContainerSBOM(t *testing.T) {
	const orgID = "whatever-org-id"
	fakeSBOMDoc := []byte("this is an sbom document")

	testServer := sbomtest.MockSBOMService(sbomtest.Response{Body: fakeSBOMDoc},
		sbomtest.AssertSBOMURLPath(t, orgID),
		sbomtest.AssertJSONBody(t, strings.TrimSpace(string(containerDepGraph))),
	)
	t.Cleanup(testServer.Close)

	// we're not re-using constants / variables for these names to ensure they match our
	// expectations as well.
	config := map[string]any{
		"format":              "cyclonedx1.4+json",
		"org":                 orgID,
		configuration.API_URL: testServer.URL,
		"targetDirectory":     "gcr.io/distroless/static:latest",
	}

	if err := sbomtest.RunCommand("container sbom", config, fakeSBOMDoc,
		containercli.Init,
		sbomtest.LegacyCLI(containerScanOutput),
	); err != nil {
		t.Fatalf("%v", err)
	}
}
