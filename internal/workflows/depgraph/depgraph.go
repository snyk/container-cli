package depgraph

import (
	"github.com/snyk/cli-extension-sbom/pkg/depgraph"
	"github.com/snyk/cli-extension-sbom/pkg/flag"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var Workflow = depgraph.NewWorkflow[*Config]("container depgraph", &Config{
	AppVulns: flag.Flag[bool]{
		Name:         "app-vulns",
		Usage:        "enable app-vulns (deprecated, as this is the default value)",
		DefaultValue: false,
	},
	ExcludeAppVulns: flag.Flag[bool]{
		Name:         "exclude-app-vulns",
		Usage:        "disable app-vulns",
		DefaultValue: false,
	},
})

func InitWorkflow(e workflow.Engine) error {
	return depgraph.InitWorkflow[*Config](e, Workflow)
}

type Config struct {
	AppVulns        flag.Flag[bool]
	ExcludeAppVulns flag.Flag[bool]
}

func (c *Config) Flags() flag.Flags {
	return flag.Flags{
		c.AppVulns,
		c.ExcludeAppVulns,
	}
}

func (*Config) Command() []string {
	return []string{"container", "test", "--print-graph", "--json"}
}
