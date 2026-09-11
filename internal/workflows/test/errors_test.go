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

package test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SkippedFilesError surfaces every skipped path so the operator can act on them.
func TestSkippedFilesError_MessageListsAllPaths(t *testing.T) {
	err := &SkippedFilesError{Paths: []string{"a.json", "b.json"}}
	assert.Contains(t, err.Error(), "a.json")
	assert.Contains(t, err.Error(), "b.json")
	assert.Contains(t, err.Error(), "2")
}

// Each error type is a standard error and survives errors.As unwrapping.
func TestErrors_AreUnwrappableViaErrorsAs(t *testing.T) {
	cases := []struct {
		name string
		err  error
		into func() any
	}{
		{
			name: "SkippedFilesError",
			err:  &SkippedFilesError{Paths: []string{"x"}},
			into: func() any { var v *SkippedFilesError; return &v },
		},
		{
			name: "ComponentFailureError",
			err:  &ComponentFailureError{Details: []string{"c"}},
			into: func() any { var v *ComponentFailureError; return &v },
		},
		{
			name: "IncompleteFindingsError",
			err:  &IncompleteFindingsError{Received: 3},
			into: func() any { var v *IncompleteFindingsError; return &v },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := tc.into()
			require.True(t, errors.As(tc.err, target))
		})
	}
}

// ComponentFailureError surfaces the platform error details in its message.
func TestComponentFailureError_NamesFailureDetails(t *testing.T) {
	err := &ComponentFailureError{Details: []string{"os scan timed out", "npm scan unauthorized"}}
	assert.Contains(t, err.Error(), "os scan timed out")
	assert.Contains(t, err.Error(), "npm scan unauthorized")
}

// IncompleteFindingsError reports how many findings were drained before the abort.
func TestIncompleteFindingsError_ReportsReceivedCount(t *testing.T) {
	err := &IncompleteFindingsError{Received: 42}
	assert.Contains(t, err.Error(), "42")
}
