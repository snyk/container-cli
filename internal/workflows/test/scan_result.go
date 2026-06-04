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
)

// scanResultSchema is the schema version written into the {schema, data} envelope.
// container-engine validates this to detect format changes across CLI versions.
const scanResultSchema = "snyk.container.scan_result.v1"

// scanResultEnvelope is the versioned wrapper written to each scan_results/scan_result_<n>.json file.
// The schema field enables container-engine to handle multiple CLI-emitted formats simultaneously
// during phased rollouts, without requiring a hard cutover.
type scanResultEnvelope struct {
	Schema string `json:"schema"`
	Data   any    `json:"data"`
}

// writeScanResultsTempDir writes each element of scanResults to
// <tmpDir>/scan_results/scan_result_<n>.json with the versioned envelope.
// The caller is responsible for deferring os.RemoveAll on tmpDir.
// Returns the root temp directory and the list of file paths written.
func writeScanResultsTempDir(scanResults []any) (tmpDir string, filePaths []string, err error) {
	tmpDir, err = os.MkdirTemp("", "container-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	subDir := filepath.Join(tmpDir, "scan_results")
	if err = os.MkdirAll(subDir, 0o755); err != nil {
		return tmpDir, nil, fmt.Errorf("failed to create scan_results subdirectory: %w", err)
	}

	paths := make([]string, 0, len(scanResults))
	for i, sr := range scanResults {
		envelope := scanResultEnvelope{
			Schema: scanResultSchema,
			Data:   sr,
		}
		bts, err := json.Marshal(envelope)
		if err != nil {
			return tmpDir, nil, fmt.Errorf("failed to marshal scan result %d: %w", i, err)
		}

		path := filepath.Join(subDir, fmt.Sprintf("scan_result_%d.json", i))
		if err = os.WriteFile(path, bts, 0o600); err != nil {
			return tmpDir, nil, fmt.Errorf("failed to write scan result %d to temp file: %w", i, err)
		}
		paths = append(paths, path)
	}

	return tmpDir, paths, nil
}
