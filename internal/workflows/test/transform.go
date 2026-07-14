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
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

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
