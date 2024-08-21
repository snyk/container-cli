// © 2023-2024 Snyk Limited All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sbom

import (
	"encoding/json"
	"errors"
	"os"
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

	sbomWorkflow *Workflow
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

	sbomWorkflow = NewWorkflow(mockSbomClient, errFactory)
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
	require.EqualError(t, err,
		errFactory.NewInvalidSbomFormatError(invalidSbomFormat, sbomconstants.SbomValidFormats).Error())
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

	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return(nil, errors.New("test error"))

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenInvalidImageReference_ShouldReturnDepGraphWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(sbomconstants.SbomValidFormats[0])
	mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")
	mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
		Return([]workflow.Data{}, nil)

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
		Return([]workflow.Data{getValidDepGraph(t, "testdata/sbom_request_depgraph.json"), getInvalidDepGraph()}, nil)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

	_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
	require.EqualError(t, err, errFactory.NewDepGraphWorkflowError(err).Error())
}

func Test_Entrypoint_GivenSbomForDepGraphError_ShouldPropagateClientError(t *testing.T) {
	type test struct {
		format string
	}

	tests := map[string]test{
		"CycloneDX 1.4 JSON": {
			format: "cyclonedx1.4+json",
		}, "CycloneDX 1.5 JSON": {
			format: "cyclonedx1.5+json",
		}, "CycloneDX 1.6 JSON": {
			format: "cyclonedx1.6+json",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			beforeEach(t)
			defer afterEach()

			require.Contains(t, sbomconstants.SbomValidFormats, tc.format)

			mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(tc.format)
			mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

			depGraphList := []workflow.Data{
				getValidDepGraph(t, "testdata/sbom_request_depgraph.json"),
				getValidDepGraph(t, "testdata/sbom_request_depgraph.json"),
			}

			mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
				Return(depGraphList, nil)
			mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

			mockSbomClient.EXPECT().GetSbomForDepGraph(
				gomock.Any(),
				"aaacbb21-19b4-44f4-8483-d03746156f6b",
				tc.format,
				&GetSbomForDepGraphRequest{
					DepGraphs: getDepGraphBytes(depGraphList),
					Subject: Subject{
						Name:    "alpine",
						Version: "3.17.0",
					},
				}).Return(nil, errFactory.NewInternalError(errors.New("test error")))

			_, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
			require.EqualError(t, err, errFactory.NewInternalError(errors.New("test error")).Error())
		})
	}
}

func Test_Entrypoint_GivenNoError_ShouldReturnSbomAsWorkflowData(t *testing.T) {
	type test struct {
		format, expectedDoc string
	}

	tests := map[string]test{
		"CycloneDX 1.4 JSON": {
			format:      "cyclonedx1.4+json",
			expectedDoc: "testdata/sbom_result_doc.json",
		}, "CycloneDX 1.5 JSON": {
			format:      "cyclonedx1.5+json",
			expectedDoc: "testdata/sbom_result_doc_cyclonedx_15.json",
		}, "CycloneDX 1.6 JSON": {
			format:      "cyclonedx1.6+json",
			expectedDoc: "testdata/sbom_result_doc_cyclonedx_16.json",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			beforeEach(t)
			defer afterEach()

			require.Contains(t, sbomconstants.SbomValidFormats, tc.format)

			mockConfig.EXPECT().GetString(flags.FlagSbomFormat.Name).Return(tc.format)
			mockConfig.EXPECT().GetString(configuration.ORGANIZATION).Return("aaacbb21-19b4-44f4-8483-d03746156f6b")

			depGraphList := []workflow.Data{getValidDepGraph(t, "testdata/sbom_request_depgraph.json")}
			mockEngine.EXPECT().InvokeWithConfig(containerdepgraph.Workflow.Identifier(), configuration.NewInMemory()).
				Return(depGraphList, nil)
			mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return("alpine:3.17.0")

			expectedSbomResult := GetSbomForDepGraphResult{
				Doc:      getSbom(t, tc.expectedDoc),
				MIMEType: "application/vnd.cyclonedx+json",
			}

			mockSbomClient.EXPECT().GetSbomForDepGraph(
				gomock.Any(),
				"aaacbb21-19b4-44f4-8483-d03746156f6b",
				tc.format,
				&GetSbomForDepGraphRequest{
					DepGraphs: getDepGraphBytes(depGraphList),
					Subject: Subject{
						Name:    "alpine",
						Version: "3.17.0",
					},
				}).Return(&expectedSbomResult, nil)

			result, err := sbomWorkflow.entrypoint(mockInvocationContext, nil)
			require.NoError(t, err)

			require.Len(t, result, 1)
			require.Equal(t, result[0].GetContentType(), expectedSbomResult.MIMEType)
			require.Equal(t, result[0].GetPayload(), expectedSbomResult.Doc)
		})
	}
}

func Test_Init_GivenWorkflowFlags_ShouldRegisterFlagsToWorkflowAndReturnThemInConfigInsteadOfNil(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	sbomWorkflow := NewWorkflow(nil, nil)

	err := sbomWorkflow.Init(engine)
	require.Nil(t, err)

	require.Len(t, sbomWorkflow.Flags, 2)

	flagSbomFormat := config.Get(flags.FlagSbomFormat.Name)
	require.NotNil(t, flagSbomFormat)

	flagExcludeAppVulns := config.Get(flags.FlagExcludeAppVulns.Name)
	require.NotNil(t, flagExcludeAppVulns)
}

func getInvalidDepGraph() workflow.Data {
	// a boolean payload (e.g. true) is not valid
	invalidDepGraph := workflow.NewData(workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"),
		constants.DataTypeDepGraph), constants.ContentTypeJSON, true)
	invalidDepGraph.SetMetaData(constants.HeaderContentLocation, "docker-image|alpine:3.17.0")
	return invalidDepGraph
}

func getValidDepGraph(t *testing.T, fileName string) workflow.Data {
	t.Helper()

	bytes, err := os.ReadFile(fileName)
	require.NoError(t, err)

	depGraph := workflow.NewData(
		workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("container depgraph"), constants.DataTypeDepGraph),
		constants.ContentTypeJSON,
		bytes,
	)
	depGraph.SetMetaData(constants.HeaderContentLocation, "docker-image|alpine:3.17.0")
	return depGraph
}

func getSbom(t *testing.T, fileName string) []byte {
	t.Helper()

	bytes, err := os.ReadFile(fileName)
	require.NoError(t, err)

	return bytes
}

func getDepGraphBytes(depGraphList []workflow.Data) []json.RawMessage {
	var expectedDepGraphBytes []json.RawMessage
	for _, depGraph := range depGraphList {
		expectedDepGraphBytes = append(expectedDepGraphBytes, depGraph.GetPayload().([]byte))
	}
	return expectedDepGraphBytes
}
