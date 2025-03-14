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

package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/require"
)

const testContainerTargetArg = "test_image:test_tag"

var (
	mockCtrl              *gomock.Controller
	mockConfig            *mocks.MockConfiguration
	mockInvocationContext *mocks.MockInvocationContext
	mockEngine            *mocks.MockEngine
	mockData              *mocks.MockData

	logger *zerolog.Logger

	unit DepGraphWorkflow
)

func beforeEach(t *testing.T) {
	mockCtrl = gomock.NewController(t)

	mockConfig = mocks.NewMockConfiguration(mockCtrl)
	mockInvocationContext = mocks.NewMockInvocationContext(mockCtrl)
	mockEngine = mocks.NewMockEngine(mockCtrl)
	mockInvocationContext.EXPECT().GetEngine().Return(mockEngine)

	mockData = mocks.NewMockData(mockCtrl)

	logger = &zlog.Logger
	unit = *Workflow
}

func afterEach() {
	mockCtrl.Finish()
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnsAnError_AndDataArrayIsEmpty_ShouldReturnTheOriginalLegacyCliWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{}
	expectedErrorMessage := "legacy cli error"
	legacyCliError := errors.New(expectedErrorMessage)

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, legacyCliError)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnsAnError_AndDataArrayIsNotEmptyAndErrorIsNotOfTypeExitError_ShouldReturnTheOriginalLegacyCliWorkflowError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{
		buildData(unit.TypeIdentifier(), nil, ""),
	}
	expectedErrorMessage := "legacy cli error"
	legacyCliNonExitError := errors.New(expectedErrorMessage)

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, legacyCliNonExitError)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnsAnError_AndDataArrayIsNotEmptyAndErrorIsOfTypeExitErrorAndPayloadCouldNotConvertFromByteArray_ShouldReturnNilError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	payload := "invalid payload type"
	legacyCliData := []workflow.Data{
		buildData(unit.TypeIdentifier(), payload, ""),
	}
	legacyCliExitError := &exec.ExitError{
		ProcessState: &os.ProcessState{},
		Stderr:       nil,
	}
	expectedErrorMessage := fmt.Sprintf("invalid payload type, want []byte, got %T", payload)

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, legacyCliExitError)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnsAnError_AndDataArrayIsNotEmptyAndErrorIsOfTypeExitErrorAndPayloadIsLegacyCliJsonError_ShouldReturnLegacyCliJsonError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	payload := []byte(`{"ok": false, "error": "legacy cli json error" , "path": "test path"}`)
	legacyCliData := []workflow.Data{
		buildData(unit.TypeIdentifier(), payload, ""),
	}
	legacyCliExitError := &exec.ExitError{
		ProcessState: &os.ProcessState{},
		Stderr:       nil,
	}
	var expectedError legacyCLIJSONError
	jsonErr := json.Unmarshal(payload, &expectedError)
	require.NoError(t, jsonErr)

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, legacyCliExitError)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.Equal(t, err, &expectedError)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsEmpty_ShouldReturnInternalError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{}
	expectedErrorMessage := internalErrorMessage

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsNil_ShouldReturnInternalError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{nil}
	expectedErrorMessage := internalErrorMessage

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsNotEmptyOrNilAndPayloadFailedToConvertToByteArray_ShouldReturnInternalError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{mockData}
	var payload interface{} = nil
	expectedErrorMessage := internalErrorMessage

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)
	mockData.EXPECT().GetPayload().Times(2).Return(payload)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsNotEmptyOrNilAndPayloadConvertToByteArrayAndTheByteArrayIsEmpty_ShouldReturnInternalError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{mockData}
	payload := []byte("")
	expectedErrorMessage := internalErrorMessage

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)
	mockData.EXPECT().GetPayload().Return(payload)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsNotEmptyOrNilAndPayloadConvertToByteArrayAndTheByteArrayIsNotEmptyAndUnableToMatchDepGraphData_ShouldReturnInternalError(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{mockData}
	payload := []byte("no depgraph data")
	expectedErrorMessage := internalErrorMessage

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)
	mockData.EXPECT().GetPayload().Return(payload)

	_, err := unit.entrypoint(mockInvocationContext, nil)

	require.EqualError(t, err, expectedErrorMessage)
}

func Test_Entrypoint_GivenLegacyCliWorkflowReturnDataArray_AndDataIsNotEmptyOrNilAndPayloadConvertToByteArrayAndTheByteArrayIsNotEmptyAndMatchMultipleDepGraphData_ShouldReturnWorkflowDataWithMultipleDepGraphsAndDepGraphsMetadata(t *testing.T) {
	beforeEach(t)
	defer afterEach()

	legacyCliData := []workflow.Data{mockData}
	var (
		depgraphData01   = "test_data_01"
		depgraphTarget01 = "test_target_01"
		depgraphData02   = "test_data_02"
		depgraphTarget02 = "test_target_02"
	)
	payload := []byte(
		fmt.Sprintf(
			"DepGraph data: %s DepGraph target: %s DepGraph end\n"+
				"DepGraph data: %s DepGraph target: %s DepGraph end",
			depgraphData01,
			depgraphTarget01,
			depgraphData02,
			depgraphTarget02,
		),
	)

	initMocks()
	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), mockConfig).Return(legacyCliData, nil)
	mockData.EXPECT().GetPayload().Return(payload)

	result, _ := unit.entrypoint(mockInvocationContext, nil)

	require.Equal(t, []byte(" "+depgraphData01+" "), result[0].GetPayload())
	require.Equal(t, constants.ContentTypeJSON, result[0].GetContentType())
	require.Equal(t, depgraphTarget01, result[0].GetContentLocation())

	require.Equal(t, []byte(" "+depgraphData02+" "), result[1].GetPayload())
	require.Equal(t, constants.ContentTypeJSON, result[1].GetContentType())
	require.Equal(t, depgraphTarget02, result[1].GetContentLocation())
}

func Test_InitWorkflow_GivenFlags_ShouldRegisterFlagsToWorkflowAndReturnThemInConfig(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := Workflow.InitWorkflow(engine)
	require.Nil(t, err)

	require.Len(t, Workflow.Flags, 1)

	flagExcludeAppVulns := config.Get(flags.FlagExcludeAppVulns.Name)
	require.NotNil(t, flagExcludeAppVulns)
}

func initMocks() {
	mockConfig.EXPECT().GetString(flags.FlagPlatform.Name).Return("")
	mockConfig.EXPECT().GetBool(flags.FlagExcludeAppVulns.Name).Return(false)
	mockConfig.EXPECT().GetString(constants.ContainerTargetArgName).Return(testContainerTargetArg)
	mockConfig.EXPECT().Set(configuration.RAW_CMD_ARGS, gomock.AssignableToTypeOf([]string{}))

	mockInvocationContext.EXPECT().GetConfiguration().Return(mockConfig)
	mockInvocationContext.EXPECT().GetEnhancedLogger().Return(logger)
}

func buildData(identifier workflow.Identifier, payload any, target string) workflow.Data {
	d := workflow.NewData(identifier, constants.ContentTypeJSON, payload)
	d.SetMetaData(constants.HeaderContentLocation, target)

	return d
}
