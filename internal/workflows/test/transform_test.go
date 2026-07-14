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

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers --------------------------------------------------------------

func makeUUID(t *testing.T, s string) openapi_types.UUID {
	t.Helper()
	var id openapi_types.UUID
	require.NoError(t, id.UnmarshalText([]byte(s)))
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

func makeBinaryEvidence(t *testing.T) testapi.Evidence {
	t.Helper()
	var e testapi.Evidence
	require.NoError(t, json.Unmarshal([]byte(`{"type":"binary_attribution"}`), &e))
	return e
}

func makeFinding(t *testing.T, id, title, severity string, locs ...testapi.FindingLocation) testapi.FindingData {
	t.Helper()
	uid := makeUUID(t, id)
	return testapi.FindingData{
		Id: &uid,
		Attributes: &testapi.FindingAttributes{
			Title:     title,
			Rating:    testapi.Rating{Severity: testapi.Severity(severity)},
			Locations: locs,
		},
	}
}

// --- filterBySeverity -----------------------------------------------------

// Empty threshold returns input unchanged.
func TestFilterBySeverity_EmptyThresholdIsPassThrough(t *testing.T) {
	in := []testapi.FindingData{
		makeFinding(t, "11111111-1111-1111-1111-111111111111", "t1", "low"),
	}
	assert.Equal(t, in, filterBySeverity(in, ""))
}

// Threshold drops findings below the rank and keeps findings at or above.
func TestFilterBySeverity_DropsBelowThresholdKeepsAtOrAbove(t *testing.T) {
	findings := []testapi.FindingData{
		makeFinding(t, "11111111-1111-1111-1111-111111111111", "low", "low"),
		makeFinding(t, "22222222-2222-2222-2222-222222222222", "medium", "medium"),
		makeFinding(t, "33333333-3333-3333-3333-333333333333", "high", "high"),
		makeFinding(t, "44444444-4444-4444-4444-444444444444", "critical", "critical"),
	}
	got := filterBySeverity(findings, "high")
	require.Len(t, got, 2)
	assert.Equal(t, "high", got[0].Attributes.Title)
	assert.Equal(t, "critical", got[1].Attributes.Title)
}

// --- separateBinaryFindings -----------------------------------------------

// A finding with binary_attribution evidence ends up in the binary slice; others stay in pkg.
func TestSeparateBinaryFindings_RoutesBinaryAttribution(t *testing.T) {
	pkgFinding := makeFinding(t, "11111111-1111-1111-1111-111111111111", "pkg", "high")
	binaryFinding := makeFinding(t, "22222222-2222-2222-2222-222222222222", "binary", "high")
	binaryFinding.Attributes.Evidence = []testapi.Evidence{makeBinaryEvidence(t)}

	pkg, binary := separateBinaryFindings([]testapi.FindingData{pkgFinding, binaryFinding})
	require.Len(t, pkg, 1)
	require.Len(t, binary, 1)
	assert.Equal(t, "pkg", pkg[0].Attributes.Title)
	assert.Equal(t, "binary", binary[0].Attributes.Title)
}

// --- regroupBySourceLocation ----------------------------------------------

// Findings without SourceLocation go to OS; findings with one bucket by file_path.
func TestRegroupBySourceLocation_SplitsOSAndApp(t *testing.T) {
	findings := []testapi.FindingData{
		makeFinding(t, "11111111-1111-1111-1111-111111111111", "os-1", "high"),
		makeFinding(t, "22222222-2222-2222-2222-222222222222", "app-1", "high", makeSourceLocation(t, "/app/package.json")),
		makeFinding(t, "33333333-3333-3333-3333-333333333333", "app-2", "high", makeSourceLocation(t, "/app/package.json")),
		makeFinding(t, "44444444-4444-4444-4444-444444444444", "app-3", "high", makeSourceLocation(t, "/srv/pom.xml")),
	}
	os, apps := regroupBySourceLocation(findings)
	require.Len(t, os, 1)
	assert.Equal(t, "os-1", os[0].Attributes.Title)
	require.Len(t, apps, 2)
	assert.Len(t, apps["/app/package.json"], 2)
	assert.Len(t, apps["/srv/pom.xml"], 1)
}

// --- findingToVuln / convertFindings --------------------------------------

// findingToVuln populates id/title/severity, and pulls package name+version from PackageLocation.
func TestConvertFindings_PopulatesPackageAndSeverity(t *testing.T) {
	finding := makeFinding(
		t,
		"11111111-1111-1111-1111-111111111111",
		"some title",
		"high",
		makePackageLocation(t, "openssl", "1.1.1d-0"),
	)

	vulns := convertFindings([]testapi.FindingData{finding}, nil, 0, nil)
	require.Len(t, vulns, 1)
	v := vulns[0]
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", v.ID)
	assert.Equal(t, "some title", v.Title)
	assert.Equal(t, "high", v.Severity)
	assert.Equal(t, "openssl", v.PackageName)
	assert.Equal(t, "openssl", v.Name)
	assert.Equal(t, "1.1.1d-0", v.Version)
}

// dockerfileInstruction is decorated from the matching meta's DockerfilePackages map.
func TestConvertFindings_DecoratesDockerfileInstruction(t *testing.T) {
	finding := makeFinding(
		t,
		"11111111-1111-1111-1111-111111111111",
		"t",
		"high",
		makePackageLocation(t, "openssl", "1.1.1d-0"),
	)
	metas := []ScanResultMeta{{
		DockerfilePackages: map[string]string{"openssl": "RUN apt-get install openssl"},
	}}

	vulns := convertFindings([]testapi.FindingData{finding}, metas, 0, nil)
	require.Len(t, vulns, 1)
	assert.Equal(t, "RUN apt-get install openssl", vulns[0].DockerfileInstruction)
}

// dockerBaseImage is decorated from the test-level BaseImageRemediationFact when present.
func TestConvertFindings_DecoratesDockerBaseImage(t *testing.T) {
	finding := makeFinding(
		t,
		"11111111-1111-1111-1111-111111111111",
		"t",
		"high",
		makePackageLocation(t, "openssl", "1.1.1d-0"),
	)
	fact := &BaseImageRemediationFact{BaseImageName: "debian:10"}

	vulns := convertFindings([]testapi.FindingData{finding}, nil, 0, fact)
	require.Len(t, vulns, 1)
	assert.Equal(t, "debian:10", vulns[0].DockerBaseImage)
}
