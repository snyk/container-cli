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

package errors

import (
	"fmt"

	containererrors "github.com/snyk/container-cli/internal/common/errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const DepGraphWorkflowUsrMsg = "an error occurred while running the underlying analysis needed to generate the depgraph"
const (
	EmptyLegacyDepGraphWorkflowPayloadResponseErrorCode = iota
	CouldNotConvertPayloadErrorCode
	CouldNotExtractOutputErrorCode
	EmptyOutputErrorCode
	ZeroMatchesMalformedOutputErrorCode
)

func newDepGraphWorkflowError(err error, userMsg string, errCode int) *containererrors.ContainerExtensionError {
	return containererrors.NewContainerExtensionError(
		err, userMsg, errCode, containererrors.DepGraphWorkflowErrCode,
	)
}

func NewEmptyLegacyDepGraphWorkflowPayloadResponseError(data []workflow.Data) *containererrors.ContainerExtensionError {
	return newDepGraphWorkflowError(
		fmt.Errorf("empty legacy depgraph workflow payload response (payload: %s)", data),
		DepGraphWorkflowUsrMsg,
		EmptyLegacyDepGraphWorkflowPayloadResponseErrorCode,
	)
}

func NewCouldNotConvertPayloadError(payload interface{}) *containererrors.ContainerExtensionError {
	return newDepGraphWorkflowError(
		fmt.Errorf("could not convert payload, expected []byte, but got '%T'", payload),
		DepGraphWorkflowUsrMsg,
		CouldNotConvertPayloadErrorCode,
	)
}

func NewCouldNotExtractOutputError(err error) *containererrors.ContainerExtensionError {
	return newDepGraphWorkflowError(
		fmt.Errorf("could not extract depGraphs from CLI output: %w", err),
		DepGraphWorkflowUsrMsg,
		CouldNotExtractOutputErrorCode,
	)
}

func NewEmptyOutputError() *containererrors.ContainerExtensionError {
	return newDepGraphWorkflowError(
		fmt.Errorf("empty output"),
		DepGraphWorkflowUsrMsg,
		EmptyOutputErrorCode,
	)
}

func NewZeroMatchesMalformedOutputError() *containererrors.ContainerExtensionError {
	return newDepGraphWorkflowError(
		fmt.Errorf("malformed output, got 0 matches"),
		DepGraphWorkflowUsrMsg,
		ZeroMatchesMalformedOutputErrorCode,
	)
}
