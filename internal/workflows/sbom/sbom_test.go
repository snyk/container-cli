package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	zlog "github.com/rs/zerolog/log"
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"
	sbomconstants "github.com/snyk/container-cli/internal/workflows/sbom/constants"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"
)

var (
	mockCtrl              *gomock.Controller
	mockConfig            *mocks.MockConfiguration
	mockEngine            *mocks.MockEngine
	mockInvocationContext *mocks.MockInvocationContext
	mockSbomClient        *MockSbomClient
	errFactory            = sbomerrors.NewSbomErrorFactory(&zlog.Logger)

	sbomWorkflow *SbomWorkflow
)

func beforeEach(t *testing.T) {
	mockCtrl = gomock.NewController(t)

	mockConfig = mocks.NewMockConfiguration(mockCtrl)
	mockConfig.EXPECT().Clone().Return(configuration.NewInMemory()).MaxTimes(1)
	mockEngine = mocks.NewMockEngine(mockCtrl)
	mockInvocationContext = mocks.NewMockInvocationContext(mockCtrl)
	mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&zlog.Logger)
	mockInvocationContext.EXPECT().GetConfiguration().Return(mockConfig)
	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine).MaxTimes(1)
	mockSbomClient = NewMockSbomClient(mockCtrl)

	sbomWorkflow = NewSbomWorkflow(mockSbomClient, errFactory)
}

func afterEach() {
	mockCtrl.Finish()
}

func Test_Entrypoint_GivenEmptyFormat_ShouldReturnEmptySbomFormatError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return("")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewEmptySbomFormatError(sbomconstants.SbomValidFormats).Error())
}

func Test_Entrypoint_GivenInvalidFormat_ShouldReturnInvalidSbomFormatError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	invalidSbomFormat := "invalid_sbom_format"
	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(invalidSbomFormat)

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewInvalidSbomFormatError(invalidSbomFormat, sbomconstants.SbomValidFormats).Error())
}

func Test_Entrypoint_GivenEmptyOrg_ShouldReturnEmptyOrgError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewEmptyOrgError().Error())
}

func Test_Entrypoint_GivenDepGraphWorkflowError_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).Return(nil, errors.New("test error"))

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenInvalidImageReference_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")
	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).Return([]workflow.Data{}, nil)

	// uppercase image references are not valid
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("AlpINE:3.17.0")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenInvalidDepGraphPayloadType_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return([]workflow.Data{getValidDepGraph(), getInvalidDepGraph()}, nil)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenSbomForDepGraphError_ShouldPropagateClientError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

	depGraphList := []workflow.Data{getValidDepGraph(), getValidDepGraph(), getValidDepGraph()}
	var expectedDepGraphBytes []json.RawMessage
	for _, depGraph := range depGraphList {
		expectedDepGraphBytes = append(expectedDepGraphBytes, depGraph.GetPayload().([]byte))
	}

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return(depGraphList, nil)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

	var sbomForDepGraphReq *GetSbomForDepGraphRequest
	mockSbomClient.EXPECT().
		GetSbomForDepGraph(gomock.Any(), "aaacbb21-19b4-44f4-8483-d03746156f6b", sbomconstants.SbomValidFormats[0], gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, _ string, req *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error) {
			sbomForDepGraphReq = req
			return nil, errFactory.NewInternalError(errors.New("test error"))
		})

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewInternalError(errors.New("test error")).Error())

	require.Equal(t, Subject{
		Name:    "alpine",
		Version: "3.17.0",
	}, sbomForDepGraphReq.Subject)
	require.ElementsMatch(t, expectedDepGraphBytes, sbomForDepGraphReq.DepGraphs)
}

func Test_Entrypoint_GivenNoError_ShouldReturnSbomAsWorkflowData(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

	depGraphList := []workflow.Data{getValidDepGraph(), getValidDepGraph(), getValidDepGraph()}
	var expectedDepGraphBytes []json.RawMessage
	for _, depGraph := range depGraphList {
		expectedDepGraphBytes = append(expectedDepGraphBytes, depGraph.GetPayload().([]byte))
	}

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return(depGraphList, nil)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

	var sbomForDepGraphReq *GetSbomForDepGraphRequest
	mockSbomClient.EXPECT().
		GetSbomForDepGraph(gomock.Any(), "aaacbb21-19b4-44f4-8483-d03746156f6b", sbomconstants.SbomValidFormats[0], gomock.Any()).
		DoAndReturn(func(_ context.Context, _ string, _ string, req *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error) {
			sbomForDepGraphReq = req
			return nil, nil
		})

	result, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.NoError(t, err)
	require.ElementsMatch(t, []workflow.Data{}, result)

	require.Equal(t, Subject{
		Name:    "alpine",
		Version: "3.17.0",
	}, sbomForDepGraphReq.Subject)
	require.ElementsMatch(t, expectedDepGraphBytes, sbomForDepGraphReq.DepGraphs)
}

func getInvalidDepGraph() workflow.Data {
	// a boolean payload (e.g. true) is not valid
	invalidDepGraph := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"),
		constants.DataTypeDepGraph), constants.ContentTypeJSON, true)
	invalidDepGraph.SetMetaData(constants.HeaderContentLocation, "package-lock.json")
	return invalidDepGraph
}

func getValidDepGraph() workflow.Data {
	invalidDepGraph := workflow.NewData(
		workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"), constants.DataTypeDepGraph),
		constants.ContentTypeJSON,
		[]byte(`
			{
			  "schemaVersion": "1.2.0",
			  "pkgManager": {
				"name": "apk"
			  },
			  "pkgs": [
				{
				  "id": "docker-image|alpine:3.17.0",
				  "info": {
					"name": "docker-image|alpine",
					"version": "3.17.0"
				  }
				},
				{
				  "id": "netbase@6.3",
				  "info": {
					"name": "netbase",
					"version": "6.3"
				  }
				}
			  ],
			  "graph": {
				"rootNodeId": "root-node",
				"nodes": [
				  {
					"nodeId": "root-node",
					"pkgId": "docker-image|alpine:3.17.0",
					"deps": [
					  {
						"nodeId": "netbase@6.3"
					  }
					]
				  },
				  {
					"nodeId": "netbase@6.3",
					"pkgId": "netbase@6.3",
					"deps": []
				  }
				]
			  }
			}
		`),
	)
	invalidDepGraph.SetMetaData(constants.HeaderContentLocation, "package-lock.json")
	return invalidDepGraph
}
