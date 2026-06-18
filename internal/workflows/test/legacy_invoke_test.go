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

const pluginResponseFixture = `{
  "scanResults": [
    {
      "name": "alpine:3.17",
      "target": {"image": "alpine:3.17"},
      "identity": {"type": "apk"},
      "facts": [
        {"type": "pluginVersion", "data": "6.5.0"},
        {
          "type": "dockerfileAnalysis",
          "data": {"dockerfilePackages": {"openssl": {"installCommand": "RUN apk add openssl"}}}
        }
      ]
    },
    {
      "name": "alpine:3.17/usr/src/app",
      "target": {"image": "alpine:3.17"},
      "identity": {"type": "npm", "targetFile": "/usr/src/app/package.json"},
      "facts": [
        {"type": "pluginVersion", "data": "6.5.0"}
      ]
    }
  ]
}`

// One ScanResultInput per scanResult; the inner ScanResult bytes round-trip back
// to the original JSON (so container-engine sees them byte-identical to the plugin output).
func TestParseScanResults_ProducesOneInputPerScanResult(t *testing.T) {
	inputs, metas, err := parseScanResults([]byte(pluginResponseFixture))
	require.NoError(t, err)
	require.Len(t, inputs, 2)
	require.Len(t, metas, 2)

	var first rawScanResult
	require.NoError(t, json.Unmarshal(inputs[0].ScanResult, &first))
	assert.Equal(t, "alpine:3.17", first.Name)
	assert.Equal(t, "apk", first.Identity.Type)
}

// The pluginVersion fact lands on each ScanResultInput so the envelope writer can stamp it.
func TestParseScanResults_ExtractsPluginVersionFromFacts(t *testing.T) {
	inputs, _, err := parseScanResults([]byte(pluginResponseFixture))
	require.NoError(t, err)
	require.Len(t, inputs, 2)
	for i, input := range inputs {
		assert.Equal(t, "6.5.0", input.PluginVersion, "input %d", i)
	}
}

// When no pluginVersion fact is present, the extracted version is empty
// (envelope writer's omitempty drops the field from the wire JSON).
func TestExtractPluginVersion_AbsentFactReturnsEmpty(t *testing.T) {
	sr := rawScanResult{Facts: []scanResultFact{
		{Type: "dockerfileAnalysis", Data: json.RawMessage(`{}`)},
	}}
	assert.Empty(t, extractPluginVersion(sr))
}

// Metadata extraction: identity.type and identity.targetFile flow through, and
// the dockerfileAnalysis fact populates DockerfilePackages.
func TestBuildScanResultMeta_PopulatesIdentityAndDockerfilePackages(t *testing.T) {
	inputs, metas, err := parseScanResults([]byte(pluginResponseFixture))
	require.NoError(t, err)
	require.Len(t, metas, 2)
	require.Len(t, inputs, 2)

	osMeta := metas[0]
	assert.Equal(t, "", osMeta.TargetFile, "OS scan result has no target file")
	assert.Equal(t, "apk", osMeta.PackageManager)
	assert.Equal(t, "RUN apk add openssl", osMeta.DockerfilePackages["openssl"])

	appMeta := metas[1]
	assert.Equal(t, "/usr/src/app/package.json", appMeta.TargetFile)
	assert.Equal(t, "npm", appMeta.PackageManager)
	assert.Empty(t, appMeta.DockerfilePackages, "no dockerfile fact on this scan result")
}

// An empty or malformed plugin response is rejected with a clear error rather
// than silently producing zero ScanResultInputs (which would lead to an empty upload).
func TestParseScanResults_RejectsEmptyResponse(t *testing.T) {
	_, _, err := parseScanResults([]byte(`{"scanResults":[]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no scanResults")
}
