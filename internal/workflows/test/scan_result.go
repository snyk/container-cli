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
package test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// scanResultSchemaPrefix is the fixed prefix of the on-disk envelope's
// schema field; the pluginVersion is appended to form the full schema value
// (e.g. "snyk.container.scan_result.9.1.1"). Encoding the plugin version in
// the schema string lets container-engine tell cohorts apart from the
// envelope alone — the plugin version is what drives the scanResult JSON
// shape. The engine reads pluginVersion authoritatively from the
// scanResult's own pluginVersion fact; the schema suffix is a discriminator
// on the envelope, not a source of truth.
const scanResultSchemaPrefix = "snyk.container.scan_result."

// ScanResultInput pairs one raw ScanResult JSON payload with the version of
// snyk-docker-plugin that produced it. The plugin version is extracted from
// the scanResult's PluginVersion fact upstream; empty string is acceptable
// when the producing cohort predates the fact.
type ScanResultInput struct {
	ScanResult    json.RawMessage
	PluginVersion string
}

// scanResultEnvelope is the on-disk wrapper for a single ScanResult inside an
// UPLOAD_REVISION workspace. The {schema, scanResult} shape is an internal
// contract between container-cli and container-engine; the engine validates
// that schema starts with scanResultSchemaPrefix.
type scanResultEnvelope struct {
	Schema     string          `json:"schema"`
	ScanResult json.RawMessage `json:"scanResult"`
}

// writeScanResultsTempDir writes each ScanResultInput to
// <tmpDir>/scan_results/scan_result_<n>.json wrapped in the v1 envelope. It
// returns the root temp directory (so the caller can defer os.RemoveAll) and
// the list of file paths written. On error after MkdirTemp succeeds, the
// caller still receives the temp dir name and is responsible for cleanup.
func writeScanResultsTempDir(scanResults []ScanResultInput) (tmpDir string, filePaths []string, err error) {
	tmpDir, err = os.MkdirTemp("", "container-scan-*")
	if err != nil {
		return "", nil, fmt.Errorf("creating temp directory: %w", err)
	}

	subDir := filepath.Join(tmpDir, "scan_results")
	if err = os.MkdirAll(subDir, 0o755); err != nil {
		return tmpDir, nil, fmt.Errorf("creating scan_results subdirectory: %w", err)
	}

	filePaths = make([]string, 0, len(scanResults))
	for i, input := range scanResults {
		path := filepath.Join(subDir, fmt.Sprintf("scan_result_%d.json", i))
		envelope := scanResultEnvelope{
			Schema:     scanResultSchemaPrefix + input.PluginVersion,
			ScanResult: input.ScanResult,
		}
		body, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			return tmpDir, filePaths, fmt.Errorf("marshalling envelope %d: %w", i, marshalErr)
		}
		if writeErr := os.WriteFile(path, body, 0o600); writeErr != nil {
			return tmpDir, filePaths, fmt.Errorf("writing %s: %w", path, writeErr)
		}
		filePaths = append(filePaths, path)
	}
	return tmpDir, filePaths, nil
}
