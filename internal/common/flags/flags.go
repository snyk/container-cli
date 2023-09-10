// © 2023 Snyk Limited All rights reserved.
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
	"github.com/snyk/go-application-framework/pkg/configuration"
)

var (
	FlagDebug = NewBoolFlag(
		configuration.DEBUG,
		false,
		"",
	)
	FlagAppVulns = NewBoolFlag(
		"app-vulns",
		false,
		"enable app-vulns (deprecated, as this is the default value)",
	)
	FlagExcludeAppVulns = NewBoolFlag(
		"exclude-app-vulns",
		false,
		"disable app-vulns",
	)
	FlagSbomFormat = NewShortHandStringFlag(
		"format",
		"f",
		"",
		fmt.Sprintf("Specify the SBOM output format. %s", constants.SbomValidFormats),
	)
)
