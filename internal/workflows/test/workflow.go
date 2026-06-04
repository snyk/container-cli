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

// Package test implements the Dragonfly-path "snyk container test" workflow.
//
// When the feature flag rollout-dfly-container-cli is on, this workflow:
//  1. Invokes the legacy TS CLI to run snyk-docker-plugin and capture ScanResult[].
//  2. Uploads ScanResults to File Upload API as a versioned revision.
//  3. Calls test-api-shim to start an async test job.
//  4. Polls until complete and drains canonical Findings.
//  5. Transforms findings back into the legacy snyk container test JSON output shape.
//
// When the flag is off, the workflow falls through to the TypeScript legacycli path,
// which is byte-for-byte identical to the pre-migration behaviour.
package test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	// featureFlagDflyContainerCLI is the remote feature flag that gates the new path.
	// The flag is looked up at runtime from Snyk's feature flag service via the GAF
	// configuration system, so the team can ramp from 0–100 % of orgs without a CLI release.
	featureFlagDflyContainerCLI = "rollout-dfly-container-cli"

	// workflowName matches the GAF routing pattern for "snyk container test".
	workflowName = "container test"
)

// TestWorkflow is the container test workflow registered in the Go Application Framework.
type TestWorkflow struct {
	workflows.BaseWorkflow
}

// Workflow is the singleton instance registered in container_cli.go.
var Workflow = &TestWorkflow{
	BaseWorkflow: workflows.BaseWorkflow{
		Name:  workflowName,
		Flags: flags.TestFlags,
	},
}

// InitWorkflow registers the workflow with the GAF engine and adds the feature flag
// to the framework's configuration so it is fetched from the flag service at runtime.
func (w *TestWorkflow) InitWorkflow(e workflow.Engine) error {
	_, err := e.Register(
		w.Identifier(),
		w.GetConfigurationOptionsFromFlagSet(),
		w.entrypoint,
	)
	if err != nil {
		return fmt.Errorf("failed to register container test workflow: %w", err)
	}

	// Register the Dragonfly rollout feature flag so the GAF fetches it from the
	// remote flag service before each invocation. Same pattern as os-flows.
	config_utils.AddFeatureFlagsToConfig(e, map[string]string{
		featureFlagDflyContainerCLI: featureFlagDflyContainerCLI,
	})

	return nil
}

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier(constants.WorkflowIdentifierLegacyCli)

// entrypoint is invoked by the GAF for every "snyk container test" invocation.
// It checks the Dragonfly feature flag and routes accordingly.
func (w *TestWorkflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	logger := ictx.GetEnhancedLogger()
	cfg := ictx.GetConfiguration()

	logger.Info().Msg("container test workflow: starting")

	if !cfg.GetBool(featureFlagDflyContainerCLI) {
		logger.Info().Msg("container test workflow: Dragonfly flag off, delegating to legacy TS path")
		return runLegacy(ictx, cfg)
	}

	logger.Info().Msg("container test workflow: Dragonfly flag on, running new path")
	return w.runDragonfly(ictx)
}

// runLegacy delegates to the TypeScript legacycli workflow unchanged.
// WORKFLOW_USE_STDIO pipes the TS CLI's stdout/stderr directly to the terminal
// instead of capturing it as a return value.
func runLegacy(ictx workflow.InvocationContext, cfg configuration.Configuration) ([]workflow.Data, error) {
	rawArgs := cfg.GetString(configuration.RAW_CMD_ARGS)
	legacyConfig := cfg.Clone()
	legacyConfig.Set(configuration.RAW_CMD_ARGS, rawArgs)
	legacyConfig.Set("WORKFLOW_USE_STDIO", true)
	return ictx.GetEngine().InvokeWithConfig(legacyCLIWorkflowID, legacyConfig)
}

// runDragonfly executes the full Dragonfly upload-test-drain-transform pipeline.
func (w *TestWorkflow) runDragonfly(ictx workflow.InvocationContext) ([]workflow.Data, error) {
	cfg := ictx.GetConfiguration()

	// Resolve org ID — required by both platform clients.
	orgIDStr := cfg.GetString(configuration.ORGANIZATION)
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID %q: %w", orgIDStr, err)
	}

	// Step 2: acquire ScanResult[] by invoking the legacy TS CLI.
	// In Phase 1 the plugin is TypeScript; native Go invocation is future work.
	scanResults, metas, err := acquireScanResults(ictx)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire scan results: %w", err)
	}

	// Construct platform clients from the framework's authenticated HTTP client.
	fuClient := setupFileUploadClient(ictx, orgID)
	testClient, err := setupTestClient(ictx)
	if err != nil {
		return nil, err
	}

	// Build policy and test config from flags.
	localPolicy, err := createLocalPolicy(ictx)
	if err != nil {
		return nil, err
	}
	testConfig := buildTestConfig(ictx, localPolicy, nil /*publishReport=nil → snyk container test*/)

	// Steps 3–7: write to temp dir, upload, start test, poll, drain findings.
	deps := flowDependencies{
		fileUpload: &gafFileUploadAdapter{client: fuClient},
		testClient: testClient,
		logger:     ictx.GetEnhancedLogger(),
	}
	result, err := runDflyFlow(
		context.Background(),
		deps,
		scanResults,
		orgID.String(),
		testConfig,
	)
	if err != nil {
		return nil, err
	}

	// Step 8: transform flat FindingData stream → legacy container output shape.
	transformInput := TransformInput{
		Findings:          result.Findings,
		ScanResultMetas:   metas,
		SeverityThreshold: cfg.GetString("severity-threshold"),
		ExcludeBaseImage:  cfg.GetBool("exclude-base-image-vulns"),
		ImagePath:         cfg.GetString(constants.ContainerTargetArgName),
		BaseImageFact:     result.TestMeta.BaseImageFact,
	}
	containerResult := Transform(transformInput)

	// Serialise to JSON and return as workflow data so the CLI framework renders it.
	bts, err := json.Marshal(containerResult)
	if err != nil {
		return nil, fmt.Errorf("failed to serialise container test result: %w", err)
	}

	data := workflow.NewData(
		workflow.NewTypeIdentifier(w.Identifier(), "containerTest"),
		constants.ContentTypeJSON,
		bts,
	)
	return []workflow.Data{data}, nil
}
