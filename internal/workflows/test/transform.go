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

// transform.go converts the flat canonical FindingData stream returned by the platform
// back into the legacy snyk container test --json output shape, preserving byte-for-byte
// compatibility with the legacy TypeScript path so existing integrations continue to work.
//
// The key structural rules (derived from cli/src/lib/formatters/test/format-test-results.ts):
//
//  1. OS findings (no SourceLocation file_path) → top-level object
//  2. App findings (SourceLocation file_path == ScanResult.identity.targetFile) → applications[]
//  3. Findings with BinaryAttributionEvidence → docker.binariesVulns (not vulnerabilities[])
//  4. dockerfileInstruction decorations come from the local dockerfileAnalysis fact
//  5. BaseImageRemediationFact on Test → reconstruct docker.baseImageRemediation
//
// This file holds the type definitions only. Transform logic ships incrementally in
// follow-on PRs under sub-ticket CN-1473.
package test

import (
	"encoding/json"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// severityOrder ranks severity strings so threshold filtering reduces to a numeric compare.
// Unknown severities rank 0, which means a finding with an unrecognised severity is dropped
// the moment any threshold is set — fail-closed by design.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// filterBySeverity drops findings below the threshold. An empty or unrecognised threshold
// keeps everything (matches legacy "no flag, no filter" behaviour).
func filterBySeverity(findings []testapi.FindingData, threshold string) []testapi.FindingData {
	if threshold == "" {
		return findings
	}
	minRank := severityOrder[strings.ToLower(threshold)]
	if minRank == 0 {
		return findings
	}
	out := make([]testapi.FindingData, 0, len(findings))
	for _, f := range findings {
		sev := ""
		if f.Attributes != nil {
			sev = strings.ToLower(string(f.Attributes.Rating.Severity))
		}
		if severityOrder[sev] >= minRank {
			out = append(out, f)
		}
	}
	return out
}

// separateBinaryFindings splits findings into package vulns and binary vulns.
// Binary vulns carry binary-attribution evidence and surface in docker.binariesVulns
// instead of vulnerabilities[].
func separateBinaryFindings(findings []testapi.FindingData) (pkg []testapi.FindingData, binary []testapi.FindingData) {
	for _, f := range findings {
		if hasBinaryEvidence(f) {
			binary = append(binary, f)
		} else {
			pkg = append(pkg, f)
		}
	}
	return pkg, binary
}

// hasBinaryEvidence returns true when any Evidence on the finding carries the
// binary_attribution discriminator. The GAF testapi Evidence union evolves over
// time; we cope with two surfaces here: the typed Discriminator() helper, and a
// raw "type" field fallback for forward-compatibility with serialised payloads
// that the typed union does not yet know about.
func hasBinaryEvidence(f testapi.FindingData) bool {
	if f.Attributes == nil {
		return false
	}
	for _, e := range f.Attributes.Evidence {
		if disc, err := e.Discriminator(); err == nil && disc == "binary_attribution" {
			return true
		}
		bts, err := e.MarshalJSON()
		if err != nil {
			continue
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(bts, &raw); err != nil {
			continue
		}
		typeVal, ok := raw["type"]
		if !ok {
			continue
		}
		var typeStr string
		if err := json.Unmarshal(typeVal, &typeStr); err == nil && typeStr == "binary_attribution" {
			return true
		}
	}
	return false
}

// regroupBySourceLocation separates OS findings (no SourceLocation file_path)
// from app findings and buckets the latter by file_path so the transformer can
// reconstruct the applications[] array later.
func regroupBySourceLocation(findings []testapi.FindingData) (
	osFindings []testapi.FindingData,
	appFindings map[string][]testapi.FindingData,
) {
	appFindings = make(map[string][]testapi.FindingData)
	for _, f := range findings {
		tf := sourceLocationFilePath(f)
		if tf == "" {
			osFindings = append(osFindings, f)
		} else {
			appFindings[tf] = append(appFindings[tf], f)
		}
	}
	return osFindings, appFindings
}

// sourceLocationFilePath extracts file_path from the first SourceLocation
// (discriminator="source") on a FindingData. OS findings have no SourceLocation
// and return "".
func sourceLocationFilePath(f testapi.FindingData) string {
	if f.Attributes == nil {
		return ""
	}
	for _, loc := range f.Attributes.Locations {
		disc, err := loc.Discriminator()
		if err != nil || disc != "source" {
			continue
		}
		sl, err := loc.AsSourceLocation()
		if err == nil && sl.FilePath != "" {
			return sl.FilePath
		}
	}
	return ""
}

// convertFindings maps a slice of canonical FindingData to the legacy
// ContainerVuln shape, decorating each vuln with the local dockerfileAnalysis
// fact (CLI-side; Registry never returned dockerfileInstruction) and the
// test-level BaseImageRemediationFact (dockerBaseImage).
func convertFindings(
	findings []testapi.FindingData,
	metas []ScanResultMeta,
	metaIdx int,
	baseImageFact *BaseImageRemediationFact,
) []ContainerVuln {
	var meta *ScanResultMeta
	if metaIdx >= 0 && metaIdx < len(metas) {
		meta = &metas[metaIdx]
	}

	vulns := make([]ContainerVuln, 0, len(findings))
	for _, f := range findings {
		v := findingToVuln(f)
		if meta != nil && len(meta.DockerfilePackages) > 0 {
			pkgBase := strings.SplitN(v.PackageName, "/", 2)[0]
			if cmd, ok := meta.DockerfilePackages[pkgBase]; ok {
				v.DockerfileInstruction = cmd
			}
		}
		if baseImageFact != nil && baseImageFact.BaseImageName != "" {
			v.DockerBaseImage = baseImageFact.BaseImageName
		}
		vulns = append(vulns, v)
	}
	return vulns
}

// findingToVuln maps a single canonical FindingData to ContainerVuln. Pulls
// package name+version from the first PackageLocation; falls back to id-as-name
// when no PackageLocation is present.
func findingToVuln(f testapi.FindingData) ContainerVuln {
	v := ContainerVuln{}
	if f.Id != nil {
		v.ID = f.Id.String()
		v.Name = v.ID
	}
	if f.Attributes == nil {
		return v
	}

	v.Title = f.Attributes.Title
	v.Severity = strings.ToLower(string(f.Attributes.Rating.Severity))

	for _, loc := range f.Attributes.Locations {
		disc, err := loc.Discriminator()
		if err != nil || disc != "package" {
			continue
		}
		pl, err := loc.AsPackageLocation()
		if err == nil {
			v.PackageName = pl.Package.Name
			v.Name = pl.Package.Name
			v.Version = pl.Package.Version
			break
		}
	}
	return v
}

// ContainerTestResult is the top-level JSON shape for snyk container test --json output.
// It mirrors the legacy TypeScript LegacyVulnerabilityResponse for docker/container.
type ContainerTestResult struct {
	OK                bool            `json:"ok"`
	Vulnerabilities   []ContainerVuln `json:"vulnerabilities"`
	DependencyCount   int             `json:"dependencyCount"`
	UniqueCount       int             `json:"uniqueCount"`
	Summary           string          `json:"summary"`
	PackageManager    string          `json:"packageManager"`
	Path              string          `json:"path"`
	ProjectName       string          `json:"projectName,omitempty"`
	DisplayTargetFile string          `json:"displayTargetFile,omitempty"`
	Docker            *DockerSection  `json:"docker,omitempty"`
	Applications      []AppResult     `json:"applications,omitempty"`
	Error             string          `json:"error,omitempty"`
}

// DockerSection holds container-specific metadata on the top-level result object.
type DockerSection struct {
	BaseImage            string                `json:"baseImage,omitempty"`
	BaseImageRemediation *BaseImageRemediation `json:"baseImageRemediation,omitempty"`
	BinariesVulns        *BinariesVulns        `json:"binariesVulns,omitempty"`
}

// BaseImageRemediation mirrors the legacy registry cli.ts formatter output shape.
// The Dragonfly platform stores data-shaped fields on BaseImageRemediationFact;
// the transformer reconstructs the presentation strings the CLI renders.
type BaseImageRemediation struct {
	Code              string            `json:"code"`
	BaseImageOutdated bool              `json:"baseImageOutdated,omitempty"`
	Advice            []RemediationLine `json:"advice"`
}

// RemediationLine is one line in the base-image advice box, optionally bold/colored.
type RemediationLine struct {
	Message string `json:"message"`
	Bold    bool   `json:"bold,omitempty"`
	Color   string `json:"color,omitempty"`
}

// BinariesVulns holds node/java binary hash vulnerabilities separately from package vulns.
type BinariesVulns struct {
	IssuesData   map[string]ContainerVuln `json:"issuesData"`
	AffectedPkgs map[string]AffectedPkg   `json:"affectedPkgs"`
}

// AffectedPkg mirrors the legacy affectedPkgs shape.
type AffectedPkg struct {
	Pkg    PkgRef              `json:"pkg"`
	Issues map[string]IssueRef `json:"issues"`
}

// PkgRef is a package name+version pair.
type PkgRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// IssueRef is a minimal issue reference inside affectedPkgs.
type IssueRef struct {
	IssueID string `json:"issueId"`
}

// ContainerVuln is one vulnerability entry in the vulnerabilities[] array.
type ContainerVuln struct {
	ID                    string   `json:"id"`
	Title                 string   `json:"title"`
	Severity              string   `json:"severity"`
	PackageName           string   `json:"packageName"`
	Version               string   `json:"version"`
	Name                  string   `json:"name"`
	Identifiers           any      `json:"identifiers,omitempty"`
	CVSSv3                string   `json:"CVSSv3,omitempty"`
	CvssScore             float64  `json:"cvssScore,omitempty"`
	Language              string   `json:"language,omitempty"`
	PackageManager        string   `json:"packageManager,omitempty"`
	FixedIn               []string `json:"fixedIn,omitempty"`
	IsUpgradable          bool     `json:"isUpgradable"`
	IsPatchable           bool     `json:"isPatchable"`
	IsFixed               bool     `json:"isFixed"`
	DockerfileInstruction string   `json:"dockerfileInstruction,omitempty"`
	DockerBaseImage       string   `json:"dockerBaseImage,omitempty"`
	From                  []string `json:"from,omitempty"`
}

// AppResult is one per-ecosystem application result nested under applications[].
type AppResult struct {
	Vulnerabilities   []ContainerVuln `json:"vulnerabilities"`
	PackageManager    string          `json:"packageManager"`
	TargetFile        string          `json:"targetFile"`
	ProjectName       string          `json:"projectName,omitempty"`
	DisplayTargetFile string          `json:"displayTargetFile,omitempty"`
	UniqueCount       int             `json:"uniqueCount"`
	DependencyCount   int             `json:"dependencyCount"`
	Summary           string          `json:"summary"`
	OK                bool            `json:"ok"`
}

// ScanResultMeta carries the per-ScanResult metadata the transformer needs for
// regrouping and decoration. Populated from the ScanResult[] acquired in the
// legacy CLI invocation (sub-ticket D).
type ScanResultMeta struct {
	// TargetFile is ScanResult.identity.targetFile — the manifest path inside the image.
	// Empty for OS ScanResults (no manifest).
	TargetFile string
	// PackageManager is ScanResult.identity.type (e.g. "deb", "npm", "maven").
	PackageManager string
	// Name is ScanResult.name (e.g. "alpine:3.17.0").
	Name string
	// DockerfilePackages maps package name → Dockerfile install command.
	// Populated from ScanResult.facts[dockerfileAnalysis].dockerfilePackages.
	// Absent when --file was not provided or the image had no Dockerfile.
	DockerfilePackages map[string]string
}

// TransformInput is everything the transformer needs.
type TransformInput struct {
	Findings          []testapi.FindingData
	ScanResultMetas   []ScanResultMeta
	SeverityThreshold string // empty = no filter
	ExcludeBaseImage  bool
	ImagePath         string // the CLI argument (e.g. "alpine:3.17.0")
	BaseImageFact     *BaseImageRemediationFact
}

// BaseImageRemediationFact carries base-image metadata from Test.Attrs.Facts[].
// container-engine writes this as a test-level fact (not a FindingData) so the
// CLI-side transformer can reconstruct the legacy advice[] presentation.
type BaseImageRemediationFact struct {
	Code              string `json:"code"`
	BaseImageName     string `json:"baseImageName"`
	BaseImageOutdated bool   `json:"baseImageOutdated"`
}
