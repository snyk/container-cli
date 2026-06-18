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

// fileUploadClient abstracts the File Upload API for testability — the real
// GAF client is wrapped by gafFileUploadAdapter to satisfy this interface.
// Keeping it narrow makes fakes a one-method surface.
type fileUploadClient interface {
	CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootDir string) (*uploadResult, error)
}

// testStarter is the subset of testapi.TestClient runDflyFlow consumes. A
// narrow interface lets unit tests fake the entire test-start/wait/drain
// chain without standing up the full GAF testapi surface.
type testStarter interface {
	StartTest(ctx context.Context, params testapi.StartTestParams) (testapi.TestHandle, error)
}

// uploadResult mirrors the fields the flow reads from fileupload.UploadResult.
// Keeping a local type insulates the orchestrator from GAF type churn.
type uploadResult struct {
	RevisionID   uuid.UUID
	SkippedFiles []string
}

// flowDependencies holds the platform clients runDflyFlow drives. Each is an
// interface so unit tests can substitute fakes without real network calls.
type flowDependencies struct {
	fileUpload fileUploadClient
	testClient testStarter
	logger     *zerolog.Logger
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

// baseImageRemediationFactType is the discriminator container-engine uses on
// the test-level fact carrying base-image data; see container-engine's
// transform package.
const baseImageRemediationFactType = "base_image_remediation"

// runDflyFlow orchestrates the full Dragonfly upload→test→drain cycle:
//  1. Write ScanResults to a versioned-envelope temp dir.
//  2. Upload the directory in one revision.
//  3. Fail-closed if any file was skipped on upload.
//  4. Build the container UploadResource and start the test.
//  5. Wait for completion; fail-closed on per-component errors.
//  6. Drain findings pagination; fail-closed if it does not reach complete.
//  7. Extract BaseImageRemediationFact from Test.Attrs.Facts[] for the
//     transformer to reconstruct the legacy advice[] block.
func runDflyFlow(
	ctx context.Context,
	deps flowDependencies,
	scanResults []ScanResultInput,
	orgID string,
	testConfig *testapi.TestConfiguration,
) (*flowResult, error) {
	logger := deps.logger

	tmpDir, filePaths, err := writeScanResultsTempDir(scanResults)
	defer func() {
		if tmpDir == "" {
			return
		}
		if rmErr := os.RemoveAll(tmpDir); rmErr != nil && logger != nil {
			logger.Warn().Err(rmErr).Str("tmpDir", tmpDir).Msg("failed to clean up temp directory")
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("writing scan results to temp dir: %w", err)
	}

	pathsChan := make(chan string, len(filePaths))
	for _, p := range filePaths {
		pathsChan <- p
	}
	close(pathsChan)

	uploadRes, err := deps.fileUpload.CreateRevisionFromChan(ctx, pathsChan, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("uploading scan results: %w", err)
	}
	if len(uploadRes.SkippedFiles) > 0 {
		return nil, &SkippedFilesError{Paths: uploadRes.SkippedFiles}
	}

	uploadResource, err := newContainerUploadResource(uploadRes.RevisionID.String())
	if err != nil {
		return nil, fmt.Errorf("creating upload resource: %w", err)
	}
	resources := []testapi.TestResourceCreateItem{uploadResource}

	startParams := testapi.NewStartTestParamsFromResources(orgID, &resources, testConfig)
	handle, err := deps.testClient.StartTest(ctx, startParams)
	if err != nil {
		return nil, fmt.Errorf("starting test: %w", err)
	}
	if err := handle.Wait(ctx); err != nil {
		return nil, fmt.Errorf("test execution: %w", err)
	}

	result := handle.Result()
	if errs := result.GetErrors(); errs != nil && len(*errs) > 0 {
		details := make([]string, 0, len(*errs))
		for _, e := range *errs {
			details = append(details, e.Detail)
		}
		return nil, &ComponentFailureError{Details: details}
	}

	var findings []testapi.FindingData
	for {
		page, complete, findErr := result.Findings(ctx)
		if findErr != nil {
			return nil, fmt.Errorf("draining findings: %w", findErr)
		}
		findings = append(findings, page...)
		if complete {
			break
		}
		if ctx.Err() != nil {
			return nil, &IncompleteFindingsError{Received: len(findings)}
		}
	}

	var baseImageFact *BaseImageRemediationFact
	if facts := result.GetTestFacts(); facts != nil {
		baseImageFact = extractBaseImageFact(*facts)
	}
	return &flowResult{
		Findings: findings,
		TestMeta: testMeta{BaseImageFact: baseImageFact},
	}, nil
}

// extractBaseImageFact looks for a fact with type "base_image_remediation" in
// Test.Attrs.Facts[] and unmarshals its data payload as BaseImageRemediationFact.
// Returns nil when no such fact is present. TestFact is a generated GAF type
// whose concrete shape may evolve; round-tripping through JSON keeps us robust
// to those changes.
func extractBaseImageFact(facts []testapi.TestFact) *BaseImageRemediationFact {
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
		if candidate.Type == baseImageRemediationFactType {
			return &candidate.Data
		}
	}
	return nil
}
