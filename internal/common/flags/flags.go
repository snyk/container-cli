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
