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

package flags

import (
	"fmt"

	"github.com/snyk/container-cli/internal/workflows/sbom/constants"
)

var (
	FlagExcludeAppVulns = NewBoolFlag(
		"exclude-app-vulns",
		false,
		"disable app-vulns",
	)
	FlagSbomFormat = NewStringFlag(
		"format",
		"",
		fmt.Sprintf("Specify the SBOM output format. %s", constants.SbomValidFormats),
	)
	FlagPlatform = NewStringFlag(
		"platform",
		"",
		fmt.Sprintf(
			"For multi-architecture images, specify the platform for the container image. %s",
			constants.ValidPlatforms,
		),
	)
	FlagUsername = NewStringFlag(
		"username",
		"",
		"Username for private registry authentication",
	)
	FlagPassword = NewStringFlag(
		"password",
		"",
		"Password for private registry authentication",
	)
	FlagExcludeNodeModules = NewBoolFlag(
		"exclude-node-modules",
		false,
		"Exclude node_modules from scanning",
	)
	FlagNestedJarsDepth = NewStringFlag(
		"nested-jars-depth",
		"",
		"Maximum depth for nested JAR scanning",
	)

	// FlagFile is the path to a Dockerfile for instruction-level annotation.
	FlagFile = NewStringFlag(
		"file",
		"",
		"Path to the Dockerfile associated with the image",
	)

	// FlagExcludeBaseImageVulns strips base-image packages from the dep graph before upload.
	FlagExcludeBaseImageVulns = NewBoolFlag(
		"exclude-base-image-vulns",
		false,
		"Exclude vulnerabilities introduced by the base image",
	)

	// Dragonfly policy flags — used by the container test workflow to build LocalPolicy.

	FlagSeverityThreshold = NewStringFlag(
		"severity-threshold",
		"",
		"Only report vulnerabilities of the specified level or higher (low|medium|high|critical)",
	)
	FlagFailOn = NewStringFlag(
		"fail-on",
		"",
		"Fail only when there are vulnerabilities that can be fixed (upgradable|all)",
	)
	FlagIgnorePolicy = NewBoolFlag(
		"ignore-policy",
		false,
		"Bypass Snyk ignore policies and .snyk files",
	)
	FlagTargetReference = NewStringFlag(
		"target-reference",
		"",
		"Target reference used to identify the test result",
	)

	// Project metadata flags — shared with os-flows.

	FlagProjectTags = NewStringFlag(
		"project-tags",
		"",
		"Project tags to associate with the test result (key=value,key=value)",
	)
	FlagProjectBusinessCriticality = NewStringFlag(
		"project-business-criticality",
		"",
		"Business criticality of the project (critical|high|medium|low)",
	)
	FlagProjectEnvironment = NewStringFlag(
		"project-environment",
		"",
		"Environment of the project (frontend|backend|internal|external|mobile|saas|onprem|hosted|distributed)",
	)
	FlagProjectLifecycle = NewStringFlag(
		"project-lifecycle",
		"",
		"Lifecycle stage of the project (production|development|sandbox)",
	)
)

// CommonFlags represents the flags that are shared between the top-level SBOM workflow
// and the internal dependency graph workflow to control the container analysis.
var CommonFlags = []Flag{
	FlagExcludeAppVulns,
	FlagPlatform,
	FlagUsername,
	FlagPassword,
	FlagExcludeNodeModules,
	FlagNestedJarsDepth,
}

// TestFlags are the flags accepted by the container test workflow.
var TestFlags = append(
	CommonFlags,
	FlagFile,
	FlagExcludeBaseImageVulns,
	FlagSeverityThreshold,
	FlagFailOn,
	FlagIgnorePolicy,
	FlagTargetReference,
	FlagProjectTags,
	FlagProjectBusinessCriticality,
	FlagProjectEnvironment,
	FlagProjectLifecycle,
)
