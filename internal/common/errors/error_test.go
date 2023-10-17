// © 2023 Snyk Limited All rights reserved.
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

package errors_test

import (
	"fmt"
	"testing"

	"github.com/snyk/container-cli/internal/common/errors"

	"github.com/stretchr/testify/require"
)

func Test_Error_GivenErrorWithUserMessageAndWithoutWorkflowError_ShouldReturnUserMessageOnly(t *testing.T) {
	err := "test error"
	userMessage := "test user message"
	errorCode := 42
	workflowErrorCode := ""

	unit := errors.NewContainerExtensionError(fmt.Errorf(err), userMessage, errorCode, workflowErrorCode)
	result := unit.Error()

	require.Equal(t, userMessage, result)
}

func Test_Error_GivenErrorWithUserMessageAndWorkflowErrorCodeAndErrorCode_ShouldReturnUserMessageAndAppendWorkflowErrorCodeAndErrorCode(t *testing.T) {
	err := "test error"
	userMessage := "test user message"
	errorCode := 42
	workflowErrorCode := "A"

	expectedErrorMessage := fmt.Sprintf("%s [ERR#%s%d]", userMessage, workflowErrorCode, errorCode)

	unit := errors.NewContainerExtensionError(fmt.Errorf(err), userMessage, errorCode, workflowErrorCode)
	result := unit.Error()

	require.Equal(t, expectedErrorMessage, result)
}

func Test_Error_GivenNestedErrorWithUserMessageAndWorkflowErrorCodeAndErrorCode_ShouldReturnUserMessageOfTheLastErrorAndAppendWorkflowErrorCodeAndErrorCodeAndTheNestedErrorWorkflowErrorCodeAndErrorCode(t *testing.T) {
	nestedErr := "test error 01"
	nestedUserMessage := "test user message 01"
	nestedWorkflowErrorCode := "B"
	nestedErrorCode := 42

	userMessage := "test user message 02"
	workflowErrorCode := "A"
	errorCode := 24

	expectedErrorMessage := fmt.Sprintf(
		"%s [ERR#%s%d+%s%d]", userMessage, workflowErrorCode, errorCode, nestedWorkflowErrorCode, nestedErrorCode,
	)

	nestedContainerExtensionError := errors.NewContainerExtensionError(
		fmt.Errorf(nestedErr), nestedUserMessage, nestedErrorCode, nestedWorkflowErrorCode,
	)
	unit := errors.NewContainerExtensionError(nestedContainerExtensionError, userMessage, errorCode, workflowErrorCode)
	result := unit.Error()

	require.Equal(t, expectedErrorMessage, result)
}
