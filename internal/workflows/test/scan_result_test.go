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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Each ScanResultInput is written to scan_results/scan_result_<n>.json wrapped
// in the {schema, scanResult} envelope, with schema carrying the plugin
// version as a suffix (e.g. "snyk.container.scan_result.6.5.0").
func TestWriteScanResultsTempDir_ProducesEnvelopes(t *testing.T) {
	inputs := []ScanResultInput{
		{ScanResult: json.RawMessage(`{"identity":{"type":"apk"}}`), PluginVersion: "6.5.0"},
		{ScanResult: json.RawMessage(`{"identity":{"type":"npm"}}`), PluginVersion: "6.5.0"},
	}

	tmpDir, paths, err := writeScanResultsTempDir(inputs)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	require.NoError(t, err)
	require.Len(t, paths, 2)

	for i, path := range paths {
		expected := filepath.Join(tmpDir, "scan_results", fmt.Sprintf("scan_result_%d.json", i))
		assert.Equal(t, expected, path, "file path should follow scan_results/scan_result_<n>.json")

		body, readErr := os.ReadFile(path)
		require.NoError(t, readErr)

		var env struct {
			Schema     string          `json:"schema"`
			ScanResult json.RawMessage `json:"scanResult"`
		}
		require.NoError(t, json.Unmarshal(body, &env))
		assert.Equal(t, "snyk.container.scan_result.6.5.0", env.Schema)
		assert.JSONEq(t, string(inputs[i].ScanResult), string(env.ScanResult))
		assert.NotContains(t, string(body), "pluginVersion",
			"pluginVersion is no longer a top-level envelope field; it rides on the schema suffix")
	}
}

// When the input carries no plugin version, the schema still ends with the
// prefix (trailing dot); the engine tolerates an empty suffix.
func TestWriteScanResultsTempDir_EmptyPluginVersion(t *testing.T) {
	inputs := []ScanResultInput{
		{ScanResult: json.RawMessage(`{"identity":{"type":"apk"}}`)},
	}

	tmpDir, paths, err := writeScanResultsTempDir(inputs)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	require.NoError(t, err)
	require.Len(t, paths, 1)

	body, err := os.ReadFile(paths[0])
	require.NoError(t, err)

	var env struct {
		Schema string `json:"schema"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Equal(t, "snyk.container.scan_result.", env.Schema)
}

// Empty input still produces a usable temp dir with the scan_results subdirectory.
func TestWriteScanResultsTempDir_EmptyInput(t *testing.T) {
	tmpDir, paths, err := writeScanResultsTempDir(nil)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	require.NoError(t, err)
	assert.Empty(t, paths)

	info, statErr := os.Stat(filepath.Join(tmpDir, "scan_results"))
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}
