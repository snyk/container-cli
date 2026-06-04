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
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// flowDependencies holds the platform clients needed by runDflyFlow.
// Keeping them behind interfaces enables unit testing without real network calls.
type flowDependencies struct {
	fileUpload fileUploadClient
	testClient testapi.TestClient
	logger     *zerolog.Logger
}

// fileUploadClient abstracts the File Upload API for testing.
type fileUploadClient interface {
	CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootDir string) (*uploadResult, error)
}

// uploadResult mirrors the fields we use from fileupload.UploadResult.
type uploadResult struct {
	RevisionID   uuid.UUID
	SkippedFiles []string
}

// flowResult is what runDflyFlow returns to the workflow entry point.
type flowResult struct {
	Findings []testapi.FindingData
	TestMeta testMeta
}

// testMeta carries test-level metadata returned alongside findings.
type testMeta struct {
	BaseImageFact *BaseImageRemediationFact
}

// runDflyFlow orchestrates the full Dragonfly upload-test-drain cycle.
func runDflyFlow(
	ctx context.Context,
	deps flowDependencies,
	scanResults []any,
	orgID string,
	testConfig *testapi.TestConfiguration,
) (*flowResult, error) {
	logger := deps.logger

	// Step 3: write ScanResults to a temp dir with versioned envelopes.
	tmpDir, filePaths, err := writeScanResultsTempDir(scanResults)
	defer func() {
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil {
			logger.Warn().Err(rmErr).Str("tmpDir", tmpDir).Msg("failed to clean up temp directory")
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to write scan results to temp dir: %w", err)
	}

	// Step 4: upload all ScanResult files in one revision.
	pathsChan := make(chan string, len(filePaths))
	for _, p := range filePaths {
		pathsChan <- p
	}
	close(pathsChan)

	uploadRes, err := deps.fileUpload.CreateRevisionFromChan(ctx, pathsChan, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to upload scan results: %w", err)
	}

	// Fail-closed: if any file was skipped the revision is incomplete.
	// Proceeding would produce a silent partial result — abort instead.
	if len(uploadRes.SkippedFiles) > 0 {
		return nil, &SkippedFilesError{Paths: uploadRes.SkippedFiles}
	}

	// Step 5: build the UploadResource.
	uploadResource, err := newContainerUploadResource(uploadRes.RevisionID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to create upload resource: %w", err)
	}
	resources := []testapi.TestResourceCreateItem{uploadResource}

	// Step 7a: start the test.
	startParams := testapi.NewStartTestParamsFromResources(orgID, &resources, testConfig)
	handle, err := deps.testClient.StartTest(ctx, startParams)
	if err != nil {
		return nil, fmt.Errorf("failed to start test: %w", err)
	}

	// Step 7b: poll until complete.
	if err = handle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("test execution failed: %w", err)
	}

	// Result() returns a non-nil TestResult after Wait() completes without error.
	result := handle.Result()

	// Fail-closed on per-component failures.
	// A partial analysis is more dangerous than no analysis because the customer may
	// proceed with a false sense of security.
	if errs := result.GetErrors(); errs != nil && len(*errs) > 0 {
		errMsgs := make([]string, 0, len(*errs))
		for _, e := range *errs {
			errMsgs = append(errMsgs, e.Detail)
		}
		return nil, &ComponentFailureError{Errors: errMsgs}
	}

	// Step 7c: drain findings (paginated).
	var findings []testapi.FindingData
	for {
		page, complete, findErr := result.Findings(ctx)
		if findErr != nil {
			return nil, fmt.Errorf("failed to drain findings: %w", findErr)
		}
		findings = append(findings, page...)
		if complete {
			break
		}
		if ctx.Err() != nil {
			return nil, &IncompleteFindingsError{Received: len(findings)}
		}
	}

	// Extract BaseImageRemediationFact from Test.Attrs.Facts[].
	// This is a container-specific test-level fact produced by container-engine.
	var baseImageFact *BaseImageRemediationFact
	if testFacts := result.GetTestFacts(); testFacts != nil {
		baseImageFact = extractBaseImageFact(*testFacts)
	}

	return &flowResult{
		Findings: findings,
		TestMeta: testMeta{BaseImageFact: baseImageFact},
	}, nil
}

// extractBaseImageFact deserialises the BaseImageRemediationFact from the test facts slice.
// container-engine encodes it as a JSON object with type="base_image_remediation".
// TestFact is currently typed as DependencyCountFact in the GAF; we round-trip through JSON
// to handle arbitrary fact types produced by container-engine.
func extractBaseImageFact[T any](facts []T) *BaseImageRemediationFact {
	for _, f := range facts {
		bts, err := json.Marshal(f)
		if err != nil {
			continue
		}
		var candidate struct {
			Type string                   `json:"type"`
			Data BaseImageRemediationFact `json:"data"`
		}
		if err := json.Unmarshal(bts, &candidate); err != nil {
			continue
		}
		if candidate.Type == "base_image_remediation" {
			return &candidate.Data
		}
	}
	return nil
}
