package container

import (
	"fmt"
	"github.com/snyk/container-cli/internal/workflows/depgraph"
	"github.com/snyk/container-cli/internal/workflows/sbom"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initialises all container cli workflows.
func Init(e workflow.Engine) error {
	if err := sbom.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container sbom workflow: %w", err)
	}
	if err := depgraph.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container depgraph workflow: %w", err)
	}
	return nil
}
