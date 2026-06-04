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
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// pluginResponse mirrors snyk-docker-plugin's PluginResponse type.
type pluginResponse struct {
	ScanResults []rawScanResult `json:"scanResults"`
}

// rawScanResult is the JSON shape of one ScanResult from snyk-docker-plugin.
// We keep it as a raw message so we can pass it verbatim to the upload envelope
// without needing a full Go type for every plugin fact.
type rawScanResult struct {
	Name            string             `json:"name,omitempty"`
	Policy          string             `json:"policy,omitempty"`
	Target          json.RawMessage    `json:"target"`
	Identity        scanResultIdentity `json:"identity"`
	Facts           []scanResultFact   `json:"facts"`
	TargetReference string             `json:"targetReference,omitempty"`
}

type scanResultIdentity struct {
	Type       string `json:"type"`
	TargetFile string `json:"targetFile,omitempty"`
}

type scanResultFact struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// dockerfileAnalysisData is the shape of the dockerfileAnalysis plugin fact.
type dockerfileAnalysisData struct {
	DockerfilePackages map[string]struct {
		InstallCommand string `json:"installCommand"`
	} `json:"dockerfilePackages"`
}

// acquireScanResults invokes the legacy TypeScript CLI to run snyk-docker-plugin
// and captures the ScanResult[] output.
//
// Phase 1 strategy: shell out via legacycli using "--print-graph --json" (same as
// the depgraph workflow) but capture the full plugin output JSON. This avoids
// rewriting the TypeScript scanner in Go, which is a separate future workstream.
func acquireScanResults(ictx workflow.InvocationContext) ([]any, []ScanResultMeta, error) {
	cfg := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	// Build the legacy CLI command with all plugin pass-through flags.
	cmdArgs := []string{"container", "test", "--print-graph", "--json"}
	for _, flag := range flags.CommonFlags {
		if arg := flag.GetAsCLIArgument(cfg); arg != "" {
			cmdArgs = append(cmdArgs, arg)
		}
	}
	if f := cfg.GetString("file"); f != "" {
		cmdArgs = append(cmdArgs, "--file="+f)
	}
	if cfg.GetBool("exclude-base-image-vulns") {
		cmdArgs = append(cmdArgs, "--exclude-base-image-vulns")
	}
	cmdArgs = append(cmdArgs, cfg.GetString(constants.ContainerTargetArgName))

	logger.Info().Msgf("container test: invoking legacy CLI: %v", cmdArgs)

	legacyCfg := cfg.Clone()
	legacyCfg.Set(configuration.RAW_CMD_ARGS, cmdArgs)
	data, err := ictx.GetEngine().InvokeWithConfig(
		workflow.NewWorkflowIdentifier(constants.WorkflowIdentifierLegacyCli),
		legacyCfg,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("legacy CLI invocation failed: %w", err)
	}
	if len(data) == 0 || data[0] == nil {
		return nil, nil, fmt.Errorf("legacy CLI returned empty response")
	}

	payload, ok := data[0].GetPayload().([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected legacy CLI payload type: %T", data[0].GetPayload())
	}

	// Parse as pluginResponse JSON. The legacy CLI with --print-graph --json outputs the
	// full plugin response; if it's wrapped in something else we fall through.
	var resp pluginResponse
	if err := json.Unmarshal(payload, &resp); err != nil || len(resp.ScanResults) == 0 {
		return nil, nil, fmt.Errorf("failed to parse ScanResults from legacy CLI output (len=%d): %w", len(payload), err)
	}

	scanResults := make([]any, 0, len(resp.ScanResults))
	metas := make([]ScanResultMeta, 0, len(resp.ScanResults))
	for _, sr := range resp.ScanResults {
		scanResults = append(scanResults, sr)
		metas = append(metas, buildScanResultMeta(sr))
	}

	return scanResults, metas, nil
}

// buildScanResultMeta extracts decoration metadata from a raw ScanResult.
func buildScanResultMeta(sr rawScanResult) ScanResultMeta {
	meta := ScanResultMeta{
		TargetFile:     sr.Identity.TargetFile,
		PackageManager: sr.Identity.Type,
		Name:           sr.Name,
	}

	// Extract dockerfileAnalysis fact for client-side dockerfileInstruction decoration.
	for _, fact := range sr.Facts {
		if fact.Type == "dockerfileAnalysis" {
			var dfa dockerfileAnalysisData
			if err := json.Unmarshal(fact.Data, &dfa); err == nil {
				meta.DockerfilePackages = make(map[string]string, len(dfa.DockerfilePackages))
				for pkg, v := range dfa.DockerfilePackages {
					meta.DockerfilePackages[pkg] = v.InstallCommand
				}
			}
			break
		}
	}

	return meta
}

// gafFileUploadAdapter wraps fileupload.Client to satisfy the fileUploadClient interface,
// translating from GAF types to our internal uploadResult type.
type gafFileUploadAdapter struct {
	client fileupload.Client
}

func (a *gafFileUploadAdapter) CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootDir string) (*uploadResult, error) {
	res, err := a.client.CreateRevisionFromChan(ctx, paths, rootDir)
	if err != nil {
		return nil, err
	}

	revID, err := uuid.Parse(res.RevisionID.String())
	if err != nil {
		return nil, fmt.Errorf("invalid revision ID from file upload: %w", err)
	}

	skipped := make([]string, 0, len(res.SkippedFiles))
	for _, sf := range res.SkippedFiles {
		skipped = append(skipped, sf.Path)
	}

	return &uploadResult{
		RevisionID:   revID,
		SkippedFiles: skipped,
	}, nil
}
