package sbom

import (
	"fmt"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"

	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/snyk/cli-extension-sbom/pkg/depgraph"
	"github.com/snyk/cli-extension-sbom/pkg/flag"
	"github.com/snyk/cli-extension-sbom/pkg/sbom"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func InitWorkflow(e workflow.Engine) error {
	w := sbom.NewWorkflow("container sbom", &containerDepGraph{
		depGraphWorkflow: containerdepgraph.Workflow,
	})

	return sbom.InitWorkflow(e, w)
}

type containerDepGraph struct {
	depGraphWorkflow *depgraph.Workflow[*containerdepgraph.Config]
}

func (o *containerDepGraph) Flags() flag.Flags { return o.depGraphWorkflow.Config.Flags() }

func (o *containerDepGraph) Invoke(engine workflow.Engine, from configuration.Configuration) ([]workflow.Data, error) {
	return engine.InvokeWithConfig(o.depGraphWorkflow.Identifier(), from.Clone())
}

func (o *containerDepGraph) Metadata(
	c configuration.Configuration, _ []workflow.Data,
) (name, version string, err error) {
	// we currently don't have a way of extracting the clean image name & potentially a digest from
	// the DepGraph output, so we use what's been passed on the command line.
	imgName := c.GetString("targetDirectory")
	ref, err := reference.Parse(imgName)
	if err != nil {
		return "", "", fmt.Errorf("could not parse container name: %w", err)
	}

	// sadly the reference library doesn't export these interfaces...
	type named interface{ Name() string }
	type digested interface{ Digest() digest.Digest }
	type tagged interface{ Tag() string }
	// shouldn't happen :-)
	n, ok := ref.(named)
	if !ok {
		return "", "", fmt.Errorf("image %q does not contain a name", imgName)
	}

	switch s := ref.(type) {
	case digested:
		return n.Name(), s.Digest().String(), nil
	case tagged:
		return n.Name(), s.Tag(), nil
	default:
		return n.Name(), "", nil
	}
}
