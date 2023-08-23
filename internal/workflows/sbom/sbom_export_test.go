package sbom

import (
	"github.com/golang/mock/gomock"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"
	"github.com/snyk/container-cli/internal/workflows/sbom/constants"
	"github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"
	"log"
	"os"
	"testing"
)

var (
	mockCtrl              *gomock.Controller
	mockConfig            *mocks.MockConfiguration
	mockInvocationContext *mocks.MockInvocationContext

	logger     = log.New(os.Stderr, "", log.LstdFlags)
	errFactory = errors.NewSbomErrorFactory(logger)

	sbom sbomWorkflow
)

func beforeEach(t *testing.T) {
	mockCtrl = gomock.NewController(t)

	mockConfig = mocks.NewMockConfiguration(mockCtrl)
	mockInvocationContext = mocks.NewMockInvocationContext(mockCtrl)

	sbom = sbomWorkflow{
		BaseWorkflow: workflows.BaseWorkflow{
			Name: "test container sbom",
			Flags: []flags.Flag{
				flags.FlagSbomFormat,
			},
		},
		depGraph: containerdepgraph.Workflow,
	}
}

func afterEach() {
	mockCtrl.Finish()
}

func Test_Entrypoint_GivenEmptyFormat_ShouldReturnEmptySbomFormatError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return("")
	mockInvocationContext.EXPECT().GetConfiguration().Return(mockConfig)
	mockInvocationContext.EXPECT().GetLogger().Return(logger)

	_, err := sbom.entrypoint(mockInvocationContext, nil)

	require.ErrorContains(t, err, errFactory.NewEmptySbomFormatError(constants.SbomValidFormats).Error())
}

func Test_Entrypoint_GivenInvalidFormat_ShouldReturnError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	invalidSbomFormat := "invalid_sbom_format"

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(invalidSbomFormat)
	mockInvocationContext.EXPECT().GetConfiguration().Return(mockConfig)
	mockInvocationContext.EXPECT().GetLogger().Return(logger)

	_, err := sbom.entrypoint(mockInvocationContext, nil)

	require.ErrorContains(t, err, errFactory.NewInvalidSbomFormatError(invalidSbomFormat, constants.SbomValidFormats).Error())
}
