package sbom

import (
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
	mockInvocationContext = mocks.NewMockInvocationContext(mockCtrl)
	mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&zlog.Logger)
	mockInvocationContext.EXPECT().GetConfiguration().Return(mockConfig)
	mockEngine = mocks.NewMockEngine(mockCtrl)
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

func Test_Entrypoint_GivenDepGraphWorkflowFail_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")
	mockConfig.EXPECT().Clone().Return(configuration.NewInMemory())

	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine)
	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).Return(nil, errors.New("test error"))

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenInvalidImageReference_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")
	mockConfig.EXPECT().Clone().Return(configuration.NewInMemory())

	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine)
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
	mockConfig.EXPECT().Clone().Return(configuration.NewInMemory())

	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine)

	// a boolean payload (e.g. true) is not valid
	invalidDepGraph := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"),
		constants.DataTypeDepGraph), constants.ContentTypeJSON, true)
	invalidDepGraph.SetMetaData(constants.HeaderContentLocation, "package-lock.json")

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return([]workflow.Data{invalidDepGraph}, nil)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

//func Test_Entrypoint_GivenX_ShouldY(t *testing.T) {
//	beforeEach(t)
//	defer afterEach()
//
//	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
//	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")
//	mockConfig.EXPECT().Clone().Return(configuration.NewInMemory())
//
//	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine)
//
//	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
//		Return([]workflow.Data{
//			// a boolean payload (e.g. true) is not valid
//			workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"), constants.DataTypeDepGraph), constants.ContentTypeJSON, true),
//		}, nil)
//	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")
//
//	_, err := sbom.entrypoint(mockInvocationContext, nil)
//	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
//}
