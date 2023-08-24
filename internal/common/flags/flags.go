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
