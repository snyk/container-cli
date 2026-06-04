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
	"os"
	"testing"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeUUID(s string) openapi_types.UUID {
	var id openapi_types.UUID
	if err := id.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return id
}

func makePackageLocation(t *testing.T, name, version string) testapi.FindingLocation {
	t.Helper()
	pl := testapi.PackageLocation{
		Package: testapi.Package{Name: name, Version: version},
		Type:    "package",
	}
	var loc testapi.FindingLocation
	require.NoError(t, loc.FromPackageLocation(pl))
	return loc
}

func makeSourceLocation(t *testing.T, filePath string) testapi.FindingLocation {
	t.Helper()
	sl := testapi.SourceLocation{
		FilePath: filePath,
		Type:     "source",
	}
	var loc testapi.FindingLocation
	require.NoError(t, loc.FromSourceLocation(sl))
	return loc
}

func makeFinding(t *testing.T, id, title, severity, pkgName, pkgVersion string, locs ...testapi.FindingLocation) testapi.FindingData {
	t.Helper()
	uid := makeUUID(id)
	return testapi.FindingData{
		Id: &uid,
		Attributes: &testapi.FindingAttributes{
			Title:     title,
			Rating:    testapi.Rating{Severity: testapi.Severity(severity)},
			Locations: locs,
		},
	}
}

func TestTransform_EmptyFindings(t *testing.T) {
	result := Transform(TransformInput{
		ImagePath: "alpine:3.17",
	})
	assert.True(t, result.OK)
	assert.Empty(t, result.Vulnerabilities)
	assert.Empty(t, result.Applications)
	assert.Equal(t, "No known vulnerabilities", result.Summary)
}

func TestTransform_OSFindingNoSourceLocation(t *testing.T) {
	pkgLoc := makePackageLocation(t, "busybox", "1.34.1")
	finding := makeFinding(t,
		"00000000-0000-0000-0000-000000000001",
		"CVE-2021-1234 in busybox", "high",
		"busybox", "1.34.1",
		pkgLoc,
	)

	result := Transform(TransformInput{
		Findings:  []testapi.FindingData{finding},
		ImagePath: "alpine:3.17",
	})

	assert.False(t, result.OK)
	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "busybox", result.Vulnerabilities[0].PackageName)
	assert.Equal(t, "high", result.Vulnerabilities[0].Severity)
	assert.Empty(t, result.Applications)
}

func TestTransform_AppFindingGoesToApplications(t *testing.T) {
	pkgLoc := makePackageLocation(t, "lodash", "4.17.15")
	srcLoc := makeSourceLocation(t, "/app/package-lock.json")
	finding := makeFinding(t,
		"00000000-0000-0000-0000-000000000002",
		"Prototype Pollution in lodash", "medium",
		"lodash", "4.17.15",
		pkgLoc, srcLoc,
	)

	metas := []ScanResultMeta{
		{PackageManager: "apk"},
		{TargetFile: "/app/package-lock.json", PackageManager: "npm", Name: "my-app"},
	}

	result := Transform(TransformInput{
		Findings:        []testapi.FindingData{finding},
		ScanResultMetas: metas,
		ImagePath:       "myapp:latest",
	})

	// result.OK is false because the app bucket has a vulnerability.
	assert.False(t, result.OK)
	// No OS vulnerabilities — the lodash finding belongs to the app bucket.
	assert.Empty(t, result.Vulnerabilities)
	require.Len(t, result.Applications, 1)
	assert.Equal(t, "/app/package-lock.json", result.Applications[0].TargetFile)
	assert.Equal(t, "npm", result.Applications[0].PackageManager)
	require.Len(t, result.Applications[0].Vulnerabilities, 1)
}

func TestTransform_SeverityFilter(t *testing.T) {
	high := makeFinding(t, "00000000-0000-0000-0000-000000000003", "high vuln", "high", "pkg", "1.0", makePackageLocation(t, "pkg", "1.0"))
	low := makeFinding(t, "00000000-0000-0000-0000-000000000004", "low vuln", "low", "pkg2", "2.0", makePackageLocation(t, "pkg2", "2.0"))

	result := Transform(TransformInput{
		Findings:          []testapi.FindingData{high, low},
		SeverityThreshold: "high",
		ImagePath:         "img:latest",
	})

	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "high", result.Vulnerabilities[0].Severity)
}

func TestTransform_DockerfileInstructionDecoration(t *testing.T) {
	pkgLoc := makePackageLocation(t, "curl", "7.68.0")
	finding := makeFinding(t, "00000000-0000-0000-0000-000000000005", "CVE in curl", "medium", "curl", "7.68.0", pkgLoc)

	metas := []ScanResultMeta{
		{
			PackageManager: "apt",
			DockerfilePackages: map[string]string{
				"curl": "RUN apt-get install -y curl",
			},
		},
	}

	result := Transform(TransformInput{
		Findings:        []testapi.FindingData{finding},
		ScanResultMetas: metas,
		ImagePath:       "myimg:1.0",
	})

	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "RUN apt-get install -y curl", result.Vulnerabilities[0].DockerfileInstruction)
}

func TestTransform_BaseImageFactSetsDockerSection(t *testing.T) {
	fact := &BaseImageRemediationFact{
		Code:          "REMEDIATION_AVAILABLE",
		BaseImageName: "ubuntu:20.04",
	}

	result := Transform(TransformInput{
		ImagePath:     "myapp:latest",
		BaseImageFact: fact,
	})

	require.NotNil(t, result.Docker)
	assert.Equal(t, "ubuntu:20.04", result.Docker.BaseImage)
	require.NotNil(t, result.Docker.BaseImageRemediation)
	assert.Equal(t, "REMEDIATION_AVAILABLE", result.Docker.BaseImageRemediation.Code)
	assert.NotEmpty(t, result.Docker.BaseImageRemediation.Advice)
}

func TestTransform_BaseImageNameDecoratesVuln(t *testing.T) {
	pkgLoc := makePackageLocation(t, "libssl", "1.1.1")
	finding := makeFinding(t, "00000000-0000-0000-0000-000000000006", "OpenSSL vuln", "high", "libssl", "1.1.1", pkgLoc)
	fact := &BaseImageRemediationFact{
		Code:          "NO_REMEDIATION_AVAILABLE",
		BaseImageName: "ubuntu:18.04",
	}

	result := Transform(TransformInput{
		Findings:      []testapi.FindingData{finding},
		BaseImageFact: fact,
		ImagePath:     "app:latest",
	})

	require.Len(t, result.Vulnerabilities, 1)
	assert.Equal(t, "ubuntu:18.04", result.Vulnerabilities[0].DockerBaseImage)
}

func TestFilterBySeverity_NoThreshold_ReturnsAll(t *testing.T) {
	findings := []testapi.FindingData{
		makeFinding(t, "00000000-0000-0000-0000-000000000001", "a", "critical", "p", "1", makePackageLocation(t, "p", "1")),
		makeFinding(t, "00000000-0000-0000-0000-000000000002", "b", "low", "p", "1", makePackageLocation(t, "p", "1")),
	}
	assert.Len(t, filterBySeverity(findings, ""), 2)
}

func TestFilterBySeverity_CriticalThreshold(t *testing.T) {
	findings := []testapi.FindingData{
		makeFinding(t, "00000000-0000-0000-0000-000000000001", "a", "critical", "p", "1", makePackageLocation(t, "p", "1")),
		makeFinding(t, "00000000-0000-0000-0000-000000000002", "b", "high", "p", "1", makePackageLocation(t, "p", "1")),
		makeFinding(t, "00000000-0000-0000-0000-000000000003", "c", "medium", "p", "1", makePackageLocation(t, "p", "1")),
		makeFinding(t, "00000000-0000-0000-0000-000000000004", "d", "low", "p", "1", makePackageLocation(t, "p", "1")),
	}
	result := filterBySeverity(findings, "critical")
	require.Len(t, result, 1)
	assert.Equal(t, testapi.Severity("critical"), result[0].Attributes.Rating.Severity)
}

func TestBuildBaseImageRemediation_AllCodes(t *testing.T) {
	codes := []string{
		"REMEDIATION_AVAILABLE",
		"NO_REMEDIATION_AVAILABLE",
		"OUTDATED_BASE_IMAGE",
		"UNTRACKED_BASE_IMAGE",
		"UNSUPPORTED_REGISTRY",
		"INVALID_BASE_IMAGE_NAME",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			fact := &BaseImageRemediationFact{Code: code, BaseImageName: "ubuntu:20.04"}
			rem := buildBaseImageRemediation(fact)
			require.NotNil(t, rem)
			assert.Equal(t, code, rem.Code)
			assert.NotEmpty(t, rem.Advice)
		})
	}
}

func TestWriteScanResultsTempDir_EnvelopeShape(t *testing.T) {
	sr := rawScanResult{
		Name:     "alpine:3.17",
		Identity: scanResultIdentity{Type: "apk"},
	}
	tmpDir, paths, err := writeScanResultsTempDir([]any{sr})
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	require.NoError(t, err)
	require.Len(t, paths, 1)

	bts, err := os.ReadFile(paths[0])
	require.NoError(t, err)

	var envelope struct {
		Schema string          `json:"schema"`
		Data   json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(bts, &envelope))
	assert.Equal(t, "snyk.container.scan_result.v1", envelope.Schema)
	assert.NotEmpty(t, envelope.Data)
}

func TestWriteScanResultsTempDir_MultipleFiles(t *testing.T) {
	scanResults := []any{
		rawScanResult{Name: "img:os", Identity: scanResultIdentity{Type: "apk"}},
		rawScanResult{Name: "img:app", Identity: scanResultIdentity{Type: "npm", TargetFile: "/app/package-lock.json"}},
	}
	tmpDir, paths, err := writeScanResultsTempDir(scanResults)
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	require.NoError(t, err)
	assert.Len(t, paths, 2)
}

func TestBuildSummary(t *testing.T) {
	assert.Equal(t, "No known vulnerabilities", buildSummary(0, 0))
	assert.Equal(t, "1 known vulnerability", buildSummary(1, 0))
	assert.Equal(t, "5 known vulnerabilities", buildSummary(5, 0))
}

