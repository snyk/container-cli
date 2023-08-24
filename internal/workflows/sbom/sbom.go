package sbom

import (
	"slices"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"
	sbomconstants "github.com/snyk/container-cli/internal/workflows/sbom/constants"
	"github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type sbomWorkflow struct {
	workflows.BaseWorkflow
	depGraph *containerdepgraph.DepGraphWorkflow
}

var Workflow = sbomWorkflow{
	BaseWorkflow: workflows.BaseWorkflow{
		Name: "container sbom",
		Flags: []flags.Flag{
			flags.FlagSbomFormat,
		},
	},
	depGraph: containerdepgraph.Workflow,
}

func (w *sbomWorkflow) InitWorkflow(e workflow.Engine) error {
	_, err := e.Register(
		w.Identifier(),
		w.GetConfigurationOptionsFromFlagSet(),
		w.entrypoint,
	)
	return err
}

// todo: maybe a better name for the callback function.. something like `runWorkflow`?
func (w *sbomWorkflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	var config = ictx.GetConfiguration()
	var logger = ictx.GetLogger()
	var errFactory = errors.NewSbomErrorFactory(logger)

	logger.Println("starting the sbom workflow") // TODO: set logger prefix with workflow imageName so that we will be able to quickly get all logs related to the workflow for debugging

	logger.Println("getting the sbom format")
	var format = flags.FlagSbomFormat.GetFlagValue(config)
	if err := validateSBOMFormat(format, sbomconstants.SbomValidFormats, errFactory); err != nil {
		return nil, err
	}

	logger.Println("getting preferred organization id")
	orgId := config.GetString(configuration.ORGANIZATION)
	if orgId == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	logger.Println("invoking depgraph workflow")
	depGraphs, err := ictx.GetEngine().InvokeWithConfig(w.depGraph.Identifier(), config.Clone())
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	imageAndVersion := config.GetString(constants.ContainerTargetArgName)
	imageName, imageVersion, err := depGraphMetadata(imageAndVersion)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}
	logger.Printf("image name: '%v', image version: '%v' \n", imageName, imageVersion)

	depGraphsBytes, err := parseDepGraph(depGraphs)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	result, err := DepGraphsToSBOM(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgId,
		depGraphsBytes,
		imageName,
		imageVersion,
		format,
		logger,
		errFactory,
	)
	if err != nil {
		return nil, err
	}

	logger.Println("successfully generated SBOM document")
	return []workflow.Data{w.newDepGraphData(result)}, nil
}

func (w *sbomWorkflow) typeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(w.Identifier(), constants.DataTypeSbom)
}

func (w *sbomWorkflow) newDepGraphData(res *SBOMResult) workflow.Data {
	return workflow.NewDataFromInput(nil, w.typeIdentifier(), res.MIMEType, res.Doc)
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
