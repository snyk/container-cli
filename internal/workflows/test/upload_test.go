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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The resulting JSON carries the revision id, content_type="container_analysis",
// upload type, and an empty file_patterns array — the exact wire shape the
// test-api-shim's container assembler expects.
func TestNewContainerUploadResource_ProducesContainerAnalysisWireShape(t *testing.T) {
	item, err := newContainerUploadResource("rev-abc-123")
	require.NoError(t, err)

	body, err := json.Marshal(item)
	require.NoError(t, err)

	var wire struct {
		Resource struct {
			ContentType  string   `json:"content_type"`
			FilePatterns []string `json:"file_patterns"`
			RevisionID   string   `json:"revision_id"`
			Type         string   `json:"type"`
			ScmContext   any      `json:"scm_context"`
		} `json:"resource"`
		Type string `json:"type"`
	}
	require.NoError(t, json.Unmarshal(body, &wire))

	assert.Equal(t, "container_analysis", wire.Resource.ContentType)
	assert.Equal(t, "rev-abc-123", wire.Resource.RevisionID)
	assert.Equal(t, "upload", wire.Resource.Type)
	assert.Equal(t, []string{}, wire.Resource.FilePatterns, "file_patterns must be an empty array, not omitted")
	assert.Nil(t, wire.Resource.ScmContext, "container resources carry no SCM context")
	assert.Equal(t, "base", wire.Type)
}
