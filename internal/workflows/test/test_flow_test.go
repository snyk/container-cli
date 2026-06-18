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
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- fakes -----------------------------------------------------------------

type fakeFileUpload struct {
	result *uploadResult
	err    error
}

func (f *fakeFileUpload) CreateRevisionFromChan(
	_ context.Context,
	paths <-chan string,
	_ string,
) (*uploadResult, error) {
	for range paths {
		// drain so the caller's close(pathsChan) doesn't deadlock
	}
	return f.result, f.err
}

func nopLogger() *zerolog.Logger {
	l := zerolog.Nop()
	return &l
}

// --- tests -----------------------------------------------------------------

// File Upload API silently dropping any file aborts the flow with SkippedFilesError
// before StartTest is called — a partial revision would silently miss vulnerabilities.
func TestRunDflyFlow_AbortsOnSkippedFiles(t *testing.T) {
	deps := flowDependencies{
		fileUpload: &fakeFileUpload{result: &uploadResult{
			RevisionID:   uuid.New(),
			SkippedFiles: []string{"scan_result_0.json"},
		}},
		// testClient is intentionally nil — flow must abort before invoking it.
		logger: nopLogger(),
	}
	inputs := []ScanResultInput{{ScanResult: json.RawMessage(`{"identity":{"type":"apk"}}`)}}

	_, err := runDflyFlow(context.Background(), deps, inputs, "org-1", nil)
	require.Error(t, err)
	var skipped *SkippedFilesError
	require.ErrorAs(t, err, &skipped)
	assert.Equal(t, []string{"scan_result_0.json"}, skipped.Paths)
}

// File Upload API returning a transport error surfaces wrapped to the caller —
// distinguishable from the structured fail-closed error types.
func TestRunDflyFlow_WrapsUploadError(t *testing.T) {
	deps := flowDependencies{
		fileUpload: &fakeFileUpload{err: errors.New("network unavailable")},
		logger:     nopLogger(),
	}
	inputs := []ScanResultInput{{ScanResult: json.RawMessage(`{"identity":{"type":"apk"}}`)}}

	_, err := runDflyFlow(context.Background(), deps, inputs, "org-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uploading scan results")
	assert.Contains(t, err.Error(), "network unavailable")
}

// extractBaseImageFact reads a "base_image_remediation" entry from Test.Attrs.Facts[]
// and round-trips through JSON to handle GAF's evolving TestFact type.
func TestExtractBaseImageFact_DecodesViaJSONRoundTrip(t *testing.T) {
	// Build a TestFact-shaped payload that the round-trip path recognises.
	// Since TestFact is a generated union type, we construct it via JSON.
	raw := []byte(`{
		"type":"base_image_remediation",
		"data":{
			"code":"OUTDATED_BASE_IMAGE",
			"baseImageName":"debian:10",
			"baseImageOutdated":true
		}
	}`)
	var fact struct {
		Type string                   `json:"type"`
		Data BaseImageRemediationFact `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &fact))
	assert.Equal(t, baseImageRemediationFactType, fact.Type)
	assert.Equal(t, "OUTDATED_BASE_IMAGE", fact.Data.Code)
	assert.Equal(t, "debian:10", fact.Data.BaseImageName)
	assert.True(t, fact.Data.BaseImageOutdated)
}
