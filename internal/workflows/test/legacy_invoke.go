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
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
)

// pluginResponse mirrors snyk-docker-plugin's PluginResponse type. Only the
// fields we read are declared; the rest of the response is irrelevant on the
// container-cli side because the engine treats scanResult bytes as opaque.
type pluginResponse struct {
	ScanResults []rawScanResult `json:"scanResults"`
}

// rawScanResult is the JSON shape of one ScanResult from snyk-docker-plugin.
// Most fields are stored as raw bytes so the writer can forward the original
// JSON byte-identical to container-engine without re-serialising.
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

// scanResultFact is one entry in scanResult.facts[]. Data is kept as raw bytes
// so callers can unmarshal into the type-specific shape they need.
type scanResultFact struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// dockerfileAnalysisData is the shape of the dockerfileAnalysis fact's data
// payload, used to decorate ContainerVuln.DockerfileInstruction client-side.
type dockerfileAnalysisData struct {
	DockerfilePackages map[string]struct {
		InstallCommand string `json:"installCommand"`
	} `json:"dockerfilePackages"`
}

// pluginVersionFactType is the type discriminator snyk-docker-plugin uses for
// its version fact. See snyk-docker-plugin/lib/facts.ts type "pluginVersion".
const pluginVersionFactType = "pluginVersion"

// dockerfileAnalysisFactType is the type discriminator for the local dockerfile
// analysis fact, which carries package → install command mappings.
const dockerfileAnalysisFactType = "dockerfileAnalysis"

// acquireScanResults invokes the legacy TypeScript CLI to run snyk-docker-plugin
// and captures the ScanResult[] output, returning per-ScanResult inputs ready
// for the envelope writer plus per-ScanResult metadata for the transformer.
//
// Phase 1 strategy: shell out via legacycli with `--print-graph --json` (same
// pattern the depgraph workflow uses) and parse the full plugin output JSON.
// Rewriting the TypeScript scanner in Go is a separate workstream.
//
//nolint:unused // Consumed by the flow orchestrator in a follow-on PR (sub-ticket E).
func acquireScanResults(ictx workflow.InvocationContext) ([]ScanResultInput, []ScanResultMeta, error) {
	cfg := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()

	cmdArgs := []string{"container", "test", "--print-graph", "--json"}
	for _, flag := range flags.CommonFlags {
		if arg := flag.GetAsCLIArgument(cfg); arg != "" {
			cmdArgs = append(cmdArgs, arg)
		}
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

	return parseScanResults(payload)
}

// parseScanResults unmarshals the legacy CLI's JSON output into the typed
// inputs the rest of the workflow needs. Exposed as a standalone function so
// tests can drive it directly without standing up a workflow engine.
func parseScanResults(payload []byte) ([]ScanResultInput, []ScanResultMeta, error) {
	var resp pluginResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil, nil, fmt.Errorf("parsing plugin response: %w", err)
	}
	if len(resp.ScanResults) == 0 {
		return nil, nil, fmt.Errorf("plugin response has no scanResults")
	}

	inputs := make([]ScanResultInput, 0, len(resp.ScanResults))
	metas := make([]ScanResultMeta, 0, len(resp.ScanResults))
	for _, sr := range resp.ScanResults {
		raw, err := json.Marshal(sr)
		if err != nil {
			return nil, nil, fmt.Errorf("re-encoding scan result: %w", err)
		}
		inputs = append(inputs, ScanResultInput{
			ScanResult:    raw,
			PluginVersion: extractPluginVersion(sr),
		})
		metas = append(metas, buildScanResultMeta(sr))
	}
	return inputs, metas, nil
}

// extractPluginVersion returns the snyk-docker-plugin version recorded inside
// scanResult.facts[type="pluginVersion"]. Returns empty string when the fact
// is absent — the envelope writer treats empty as "emitter cohort predates
// the field" and omits the JSON field.
func extractPluginVersion(sr rawScanResult) string {
	for _, fact := range sr.Facts {
		if fact.Type != pluginVersionFactType {
			continue
		}
		var version string
		if err := json.Unmarshal(fact.Data, &version); err == nil {
			return version
		}
	}
	return ""
}

// buildScanResultMeta extracts per-ScanResult metadata the transformer needs
// for regrouping and dockerfileInstruction decoration.
func buildScanResultMeta(sr rawScanResult) ScanResultMeta {
	meta := ScanResultMeta{
		TargetFile:     sr.Identity.TargetFile,
		PackageManager: sr.Identity.Type,
		Name:           sr.Name,
	}
	for _, fact := range sr.Facts {
		if fact.Type != dockerfileAnalysisFactType {
			continue
		}
		var dfa dockerfileAnalysisData
		if err := json.Unmarshal(fact.Data, &dfa); err != nil {
			break
		}
		meta.DockerfilePackages = make(map[string]string, len(dfa.DockerfilePackages))
		for pkg, v := range dfa.DockerfilePackages {
			meta.DockerfilePackages[pkg] = v.InstallCommand
		}
		break
	}
	return meta
}
