// © 2023-2026 Snyk Limited All rights reserved.
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

import "fmt"

func (ef *ErrorFactory) NewEmptyOrgError() *ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("failed to determine org id"),
		"Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	)
}
