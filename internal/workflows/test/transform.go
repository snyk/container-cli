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
package test

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// severityOrder maps severity strings to a numeric rank for threshold filtering.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// ContainerTestResult is the top-level JSON shape for snyk container test --json output.
// It mirrors the legacy TypeScript LegacyVulnerabilityResponse for docker/container.
type ContainerTestResult struct {
	OK                bool           `json:"ok"`
	Vulnerabilities   []ContainerVuln `json:"vulnerabilities"`
	DependencyCount   int            `json:"dependencyCount"`
	UniqueCount       int            `json:"uniqueCount"`
	Summary           string         `json:"summary"`
	PackageManager    string         `json:"packageManager"`
	Path              string         `json:"path"`
	ProjectName       string         `json:"projectName,omitempty"`
	DisplayTargetFile string         `json:"displayTargetFile,omitempty"`
	Docker            *DockerSection `json:"docker,omitempty"`
	Applications      []AppResult    `json:"applications,omitempty"`
	Error             string         `json:"error,omitempty"`
}

// DockerSection holds container-specific metadata on the top-level result object.
type DockerSection struct {
	BaseImage            string                `json:"baseImage,omitempty"`
	BaseImageRemediation *BaseImageRemediation `json:"baseImageRemediation,omitempty"`
	BinariesVulns        *BinariesVulns        `json:"binariesVulns,omitempty"`
}

// BaseImageRemediation mirrors the legacy registry cli.ts formatter output shape.
// The Dragonfly platform stores data-shaped fields on BaseImageRemediationFact;
// this transformer reconstructs the presentation strings the CLI renders.
type BaseImageRemediation struct {
	Code              string           `json:"code"`
	BaseImageOutdated bool             `json:"baseImageOutdated,omitempty"`
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

// ScanResultMeta carries the per-ScanResult metadata we need for regrouping and decoration.
// It is populated from the ScanResult[] acquired in the legacy CLI invocation.
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
// container-engine writes this as a test-level fact (not a FindingData) so it is
// accessible to the transformer here.
type BaseImageRemediationFact struct {
	Code              string `json:"code"`
	BaseImageName     string `json:"baseImageName"`
	BaseImageOutdated bool   `json:"baseImageOutdated"`
}

// Transform converts the flat FindingData stream into the legacy container test output shape.
func Transform(input TransformInput) ContainerTestResult {
	// Step 1: apply severity threshold filter before regrouping.
	filtered := filterBySeverity(input.Findings, input.SeverityThreshold)

	// Step 2: separate binary vulns (BinaryAttributionEvidence) from package vulns.
	packageFindings, binaryFindings := separateBinaryFindings(filtered)

	// Step 3: regroup package findings by SourceLocation.file_path.
	// OS findings (no SourceLocation) → index -1 (collected as osFindings).
	// App findings → matched to ScanResultMeta by TargetFile.
	osFindings, appBuckets := regroupBySourceLocation(packageFindings, input.ScanResultMetas)

	// Step 4: convert OS findings to ContainerVuln, decorate with dockerfile + baseImage.
	osVulns := convertFindings(osFindings, input.ScanResultMetas, 0, input.BaseImageFact)

	// Step 5: build DockerSection.
	dockerSection := buildDockerSection(input.BaseImageFact, binaryFindings)

	// Step 6: build applications[] from app buckets.
	apps := buildApplications(appBuckets, input.ScanResultMetas)

	// Step 7: assemble top-level result.
	result := ContainerTestResult{
		OK:             len(osVulns) == 0 && allAppsOK(apps),
		Vulnerabilities: osVulns,
		UniqueCount:    len(osVulns),
		PackageManager: osPkgManager(input.ScanResultMetas),
		Path:           input.ImagePath,
		Docker:         dockerSection,
		Applications:   apps,
		Summary:        buildSummary(len(osVulns), len(apps)),
	}
	return result
}

// filterBySeverity drops findings below the threshold. An empty threshold keeps everything.
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
// Binary vulns carry BinaryAttributionEvidence and must appear in docker.binariesVulns.
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

func hasBinaryEvidence(f testapi.FindingData) bool {
	if f.Attributes == nil {
		return false
	}
	for _, e := range f.Attributes.Evidence {
		// BinaryAttributionEvidence is signalled by discriminator type "binary_attribution".
		disc, err := e.Discriminator()
		if err == nil && disc == "binary_attribution" {
			return true
		}
		// Fallback: check the raw JSON for a "type" field.
		var raw map[string]json.RawMessage
		if bts, marshalErr := e.MarshalJSON(); marshalErr == nil {
			if jsonErr := json.Unmarshal(bts, &raw); jsonErr == nil {
				if typeVal, ok := raw["type"]; ok {
					var typeStr string
					if jsonErr := json.Unmarshal(typeVal, &typeStr); jsonErr == nil && typeStr == "binary_attribution" {
						return true
					}
				}
			}
		}
	}
	return false
}

// regroupBySourceLocation separates OS findings (no SourceLocation) from app findings
// and groups the latter by their TargetFile so we can reconstruct applications[].
func regroupBySourceLocation(findings []testapi.FindingData, _ []ScanResultMeta) (os []testapi.FindingData, apps map[string][]testapi.FindingData) {
	apps = make(map[string][]testapi.FindingData)
	for _, f := range findings {
		tf := sourceLocationFilePath(f)
		if tf == "" {
			os = append(os, f)
		} else {
			apps[tf] = append(apps[tf], f)
		}
	}
	return os, apps
}

// sourceLocationFilePath extracts the file_path from the first SourceLocation (discriminator="source")
// on a FindingData. Returns "" for OS findings which have no SourceLocation.
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

// convertFindings converts a slice of canonical FindingData to the legacy ContainerVuln shape.
// metaIdx is the index into ScanResultMetas for decoration purposes (0 = OS).
func convertFindings(findings []testapi.FindingData, metas []ScanResultMeta, metaIdx int, baseImageFact *BaseImageRemediationFact) []ContainerVuln {
	var meta *ScanResultMeta
	if metaIdx >= 0 && metaIdx < len(metas) {
		meta = &metas[metaIdx]
	}

	vulns := make([]ContainerVuln, 0, len(findings))
	for _, f := range findings {
		v := findingToVuln(f)

		// dockerfileInstruction decoration from local dockerfileAnalysis fact.
		// This was always client-side — Registry never returned it.
		if meta != nil && len(meta.DockerfilePackages) > 0 {
			pkgBase := strings.SplitN(v.PackageName, "/", 2)[0]
			if cmd, ok := meta.DockerfilePackages[pkgBase]; ok {
				v.DockerfileInstruction = cmd
			}
		}

		// dockerBaseImage comes from the test-level BaseImageRemediationFact.
		if baseImageFact != nil && baseImageFact.BaseImageName != "" {
			v.DockerBaseImage = baseImageFact.BaseImageName
		}

		vulns = append(vulns, v)
	}
	return vulns
}

// findingToVuln maps a canonical FindingData to the legacy ContainerVuln shape.
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

	// Package name and version from the first PackageLocation (discriminator="package").
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

// buildDockerSection assembles the docker: section on the top-level result.
func buildDockerSection(fact *BaseImageRemediationFact, binaryFindings []testapi.FindingData) *DockerSection {
	if fact == nil && len(binaryFindings) == 0 {
		return nil
	}

	d := &DockerSection{}

	if fact != nil {
		d.BaseImage = fact.BaseImageName
		d.BaseImageRemediation = buildBaseImageRemediation(fact)
	}

	if len(binaryFindings) > 0 {
		d.BinariesVulns = buildBinariesVulns(binaryFindings)
	}

	return d
}

// buildBaseImageRemediation reconstructs the legacy presentation-shaped advice array from the
// structured BaseImageRemediationFact. This ports the logic from
// registry/src/lib/domain/needs-refactoring/docker/cli.ts formatCliResponse and friends.
func buildBaseImageRemediation(fact *BaseImageRemediationFact) *BaseImageRemediation {
	if fact == nil {
		return nil
	}

	remediation := &BaseImageRemediation{
		Code:              fact.Code,
		BaseImageOutdated: fact.BaseImageOutdated,
	}

	switch fact.Code {
	case "REMEDIATION_AVAILABLE":
		remediation.Advice = formatRemediationAvailable(fact)
	case "NO_REMEDIATION_AVAILABLE":
		remediation.Advice = formatNoRemediationAvailable(fact)
	case "OUTDATED_BASE_IMAGE":
		remediation.Advice = formatOutdatedBaseImage(fact)
	case "UNTRACKED_BASE_IMAGE":
		remediation.Advice = []RemediationLine{
			{Message: "Base image is not tracked by Snyk. To get base image upgrade recommendations, use an official image."},
		}
	case "UNSUPPORTED_REGISTRY":
		remediation.Advice = []RemediationLine{
			{Message: "Base image is from an unsupported registry. Snyk currently supports Docker Hub and select registries."},
		}
	case "INVALID_BASE_IMAGE_NAME":
		remediation.Advice = []RemediationLine{
			{Message: "Could not parse base image name from the Dockerfile."},
		}
	}

	return remediation
}

func formatRemediationAvailable(fact *BaseImageRemediationFact) []RemediationLine {
	return []RemediationLine{
		{Message: fmt.Sprintf("Upgrade your base image from %s to a newer version:", fact.BaseImageName), Bold: true},
		{Message: fmt.Sprintf("We recommend upgrading to a newer tag of %s to fix the vulnerabilities.", fact.BaseImageName)},
	}
}

func formatNoRemediationAvailable(fact *BaseImageRemediationFact) []RemediationLine {
	return []RemediationLine{
		{Message: fmt.Sprintf("No upgrade available for base image %s.", fact.BaseImageName), Bold: true},
		{Message: "Consider using a different base image."},
	}
}

func formatOutdatedBaseImage(fact *BaseImageRemediationFact) []RemediationLine {
	return []RemediationLine{
		{Message: fmt.Sprintf("Your base image %s is outdated.", fact.BaseImageName), Bold: true},
		{Message: "Upgrade to a newer tag to get security fixes."},
	}
}

// buildBinariesVulns converts binary attribution findings to the legacy binariesVulns shape.
func buildBinariesVulns(findings []testapi.FindingData) *BinariesVulns {
	bv := &BinariesVulns{
		IssuesData:   make(map[string]ContainerVuln),
		AffectedPkgs: make(map[string]AffectedPkg),
	}
	for _, f := range findings {
		v := findingToVuln(f)
		bv.IssuesData[v.ID] = v

		pkgKey := v.PackageName + "@" + v.Version
		ap, exists := bv.AffectedPkgs[pkgKey]
		if !exists {
			ap = AffectedPkg{
				Pkg:    PkgRef{Name: v.PackageName, Version: v.Version},
				Issues: make(map[string]IssueRef),
			}
		}
		ap.Issues[v.ID] = IssueRef{IssueID: v.ID}
		bv.AffectedPkgs[pkgKey] = ap
	}
	return bv
}

// buildApplications builds the applications[] slice from per-targetFile finding buckets.
func buildApplications(appBuckets map[string][]testapi.FindingData, metas []ScanResultMeta) []AppResult {
	if len(appBuckets) == 0 {
		return nil
	}

	apps := make([]AppResult, 0, len(appBuckets))
	for tf, findings := range appBuckets {
		metaIdx := findMetaByTargetFile(metas, tf)
		vulns := convertFindings(findings, metas, metaIdx, nil)

		var pm, name string
		if metaIdx >= 0 {
			pm = metas[metaIdx].PackageManager
			name = metas[metaIdx].Name
		}

		apps = append(apps, AppResult{
			Vulnerabilities:   vulns,
			PackageManager:    pm,
			TargetFile:        tf,
			ProjectName:       name,
			DisplayTargetFile: tf,
			UniqueCount:       len(vulns),
			OK:                len(vulns) == 0,
			Summary:           buildSummary(len(vulns), 0),
		})
	}
	return apps
}

func findMetaByTargetFile(metas []ScanResultMeta, targetFile string) int {
	for i, m := range metas {
		if m.TargetFile == targetFile {
			return i
		}
	}
	return -1
}

func osPkgManager(metas []ScanResultMeta) string {
	if len(metas) > 0 {
		return metas[0].PackageManager
	}
	return ""
}

func allAppsOK(apps []AppResult) bool {
	for _, a := range apps {
		if !a.OK {
			return false
		}
	}
	return true
}

func buildSummary(vulnCount, appCount int) string {
	_ = appCount
	if vulnCount == 0 {
		return "No known vulnerabilities"
	}
	if vulnCount == 1 {
		return "1 known vulnerability"
	}
	return fmt.Sprintf("%d known vulnerabilities", vulnCount)
}
