package sbom

import (
	"context"
	"slices"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"
	sbomconstants "github.com/snyk/container-cli/internal/workflows/sbom/constants"
	"github.com/snyk/container-cli/internal/workflows/sbom/errors"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type SbomWorkflow struct {
	workflows.BaseWorkflow
	depGraph   *containerdepgraph.DepGraphWorkflow
	sbomClient SbomClient
	errFactory *sbomerrors.SbomErrorFactory
}

func NewSbomWorkflow(sbomClient SbomClient, errFactory *sbomerrors.SbomErrorFactory) *SbomWorkflow {
	return &SbomWorkflow{
		BaseWorkflow: workflows.BaseWorkflow{
			Name: "container sbom",
			Flags: []flags.Flag{
				flags.FlagSbomFormat,
			},
		},
		depGraph:   containerdepgraph.Workflow,
		sbomClient: sbomClient,
		errFactory: errFactory,
	}
}

func (w *SbomWorkflow) InitWorkflow(e workflow.Engine) error {
	_, err := e.Register(
		w.Identifier(),
		w.GetConfigurationOptionsFromFlagSet(),
		w.entrypoint,
	)
	return err
}

// todo: maybe a better name for the callback function.. something like `runWorkflow`?
func (w *SbomWorkflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	var logger = ictx.GetEnhancedLogger()
	logger.Info().Msg("starting the sbom workflow")

	var config = ictx.GetConfiguration()

	logger.Debug().Msg("getting the sbom format")
	var format = flags.FlagSbomFormat.GetFlagValue(config)
	if err := validateSBOMFormat(format, sbomconstants.SbomValidFormats, w.errFactory); err != nil {
		return nil, err
	}

	logger.Debug().Msg("getting preferred organization id")
	orgId := config.GetString(configuration.ORGANIZATION)
	if orgId == "" {
		return nil, w.errFactory.NewEmptyOrgError()
	}

	logger.Debug().Msg("invoking depgraph workflow")
	depGraphs, err := ictx.GetEngine().InvokeWithConfig(w.depGraph.Identifier(), config.Clone())
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	imageAndVersion := config.GetString(constants.ContainerTargetArgName)
	imageName, imageVersion, err := depGraphMetadata(imageAndVersion)
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	logger.Debug().Msgf("image name: '%v', image version: '%v'", imageName, imageVersion)
	depGraphsBytes, err := parseDepGraph(depGraphs)
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	sbomResult, err := w.sbomClient.GetSbomForDepGraph(context.Background(), orgId, format, &GetSbomForDepGraphRequest{
		DepGraphs: depGraphsBytes,
		Subject: Subject{
			Name:    imageName,
			Version: imageVersion,
		},
	})
	if err != nil {
		return nil, err
	}

	logger.Info().Msg("successfully generated SBOM document")
	return []workflow.Data{
		workflow.NewDataFromInput(nil, w.typeIdentifier(), sbomResult.MIMEType, sbomResult.Doc),
	}, nil
}

func (w *SbomWorkflow) typeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(w.Identifier(), constants.DataTypeSbom)
}

func validateSBOMFormat(candidate string, sbomFormats []string, errFactory *errors.SbomErrorFactory) error {
	if candidate == "" {
		return errFactory.NewEmptySbomFormatError(sbomFormats)
	}

	if slices.Contains(sbomFormats, candidate) == false {
		return errFactory.NewInvalidSbomFormatError(candidate, sbomFormats)
	}

	return nil
}
