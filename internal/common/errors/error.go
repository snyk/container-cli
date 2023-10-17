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
	"errors"
	"fmt"
)

type ContainerExtensionError struct {
	err             error
	userMsg         string
	errCode         int
	workflowErrCode string
}

func NewContainerExtensionError(
	err error, userMsg string, errorCode int, workflowErrorCode string,
) *ContainerExtensionError {
	return &ContainerExtensionError{
		err:             err,
		userMsg:         userMsg,
		errCode:         errorCode,
		workflowErrCode: workflowErrorCode,
	}
}

func (xerr *ContainerExtensionError) Error() string {
	result := xerr.userMsg
	if xerr.workflowErrCode != "" {
		result += fmt.Sprintf(" [ERR#%s]", xerr.fullErrorCode())
	}

	return result
}

func (xerr *ContainerExtensionError) fullErrorCode() string {
	prevErrCode := ""
	var prevErr *ContainerExtensionError
	if errors.As(xerr.err, &prevErr) {
		prevErrCode = "+" + prevErr.fullErrorCode()
	}

	return fmt.Sprintf("%s%d%s", xerr.workflowErrCode, xerr.errCode, prevErrCode)
}
