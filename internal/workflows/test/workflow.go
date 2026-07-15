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

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
)

// workflowName matches the GAF routing pattern for "snyk container test".
const workflowName = "container test"

// TestWorkflow is the container test workflow registered in the Go Application Framework.
type TestWorkflow struct {
	workflows.BaseWorkflow
}

// Workflow is the singleton instance registered in container_cli.go's Init().
var Workflow = &TestWorkflow{
	BaseWorkflow: workflows.BaseWorkflow{
		Name:  workflowName,
		Flags: flags.TestFlags,
	},
}

// InitWorkflow registers the workflow with the GAF engine.
func (w *TestWorkflow) InitWorkflow(e workflow.Engine) error {
	if _, err := e.Register(
		w.Identifier(),
		w.GetConfigurationOptionsFromFlagSet(),
		w.entrypoint,
	); err != nil {
		return fmt.Errorf("registering container test workflow: %w", err)
	}
	return nil
}

// entrypoint is invoked by the GAF for every "snyk container test" run and
// executes the Dragonfly pipeline unconditionally.
func (w *TestWorkflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	ictx.GetEnhancedLogger().Info().Msg("container test workflow: starting")
	return w.runDragonfly(ictx)
}

// runDragonfly executes the full upload→test→drain→transform pipeline.
func (w *TestWorkflow) runDragonfly(ictx workflow.InvocationContext) ([]workflow.Data, error) {
	cfg := ictx.GetConfiguration()

	orgIDStr := cfg.GetString(configuration.ORGANIZATION)
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID %q: %w", orgIDStr, err)
	}

	scanResults, metas, err := acquireScanResults(ictx)
	if err != nil {
		return nil, fmt.Errorf("acquiring scan results: %w", err)
	}

	fuClient := setupFileUploadClient(ictx, orgID)
	testClient, err := setupTestClient(ictx)
	if err != nil {
		return nil, err
	}

	localPolicy, err := BuildLocalPolicy(cfg)
	if err != nil {
		return nil, err
	}
	testConfig := BuildTestConfiguration(localPolicy)

	logger := ictx.GetEnhancedLogger()
	deps := flowDependencies{
		fileUpload: &gafFileUploadAdapter{client: fuClient},
		testClient: testClient,
		logger:     logger,
	}
	result, err := runDflyFlow(context.Background(), deps, scanResults, orgID.String(), testConfig)
	if err != nil {
		return nil, err
	}

	containerResult := Transform(TransformInput{
		Findings:          result.Findings,
		ScanResultMetas:   metas,
		SeverityThreshold: flags.FlagSeverityThreshold.GetFlagValue(cfg),
		ExcludeBaseImage:  flags.FlagExcludeBaseImageVulns.GetFlagValue(cfg),
		ImagePath:         cfg.GetString(constants.ContainerTargetArgName),
		BaseImageFact:     result.TestMeta.BaseImageFact,
	})

	bts, err := json.Marshal(containerResult)
	if err != nil {
		return nil, fmt.Errorf("serialising container test result: %w", err)
	}
	data := workflow.NewData(
		workflow.NewTypeIdentifier(w.Identifier(), "containerTest"),
		constants.ContentTypeJSON,
		bts,
	)
	return []workflow.Data{data}, nil
}

// gafFileUploadAdapter wraps the real fileupload.Client to satisfy the
// flow's narrower fileUploadClient interface. The conversion translates from
// GAF's typed UploadResult into our local uploadResult shape.
type gafFileUploadAdapter struct {
	client fileupload.Client
}

func (a *gafFileUploadAdapter) CreateRevisionFromChan(
	ctx context.Context,
	paths <-chan string,
	rootDir string,
) (*uploadResult, error) {
	res, err := a.client.CreateRevisionFromChan(ctx, paths, rootDir)
	if err != nil {
		return nil, err
	}
	skipped := make([]string, 0, len(res.SkippedFiles))
	for _, sf := range res.SkippedFiles {
		skipped = append(skipped, sf.Path)
	}
	return &uploadResult{
		RevisionID:   res.RevisionID,
		SkippedFiles: skipped,
	}, nil
}
