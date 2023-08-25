package container

import (
	"fmt"

	"github.com/snyk/container-cli/internal/workflows/depgraph"
	"github.com/snyk/container-cli/internal/workflows/sbom"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initialises all container cli workflows.
func Init(e workflow.Engine) error {
	if err := initSbomWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container sbom workflow: %w", err)
	}

	if err := depgraph.Workflow.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container depgraph workflow: %w", err)
	}

	return nil
}

func initSbomWorkflow(e workflow.Engine) error {
	errFactory := sbomerrors.NewSbomErrorFactory(e.GetLogger())

	sbomWorkflow := sbom.NewWorkflow(sbom.NewHttpSbomClient(sbom.HttpSbomClientConfig{
		ApiUrl:     e.GetConfiguration().GetString(configuration.API_URL),
		HttpClient: e.GetNetworkAccess().GetHttpClient(),
		Logger:     e.GetLogger(),
		ErrFactory: errFactory,
	}), errFactory)

	return sbomWorkflow.Init(e)
}
