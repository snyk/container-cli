package workflows

import (
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

type BaseWorkflow struct {
	Name  string
	Flags []flags.Flag
}

func (w *BaseWorkflow) Identifier() workflow.Identifier {
	return workflow.NewWorkflowIdentifier(w.Name)
}
func (w *BaseWorkflow) GetConfigurationOptionsFromFlagSet() workflow.ConfigurationOptions {
	fs := pflag.NewFlagSet(w.Name, pflag.ExitOnError)

	for _, f := range w.Flags {
		fs.AddFlagSet(f.GetFlagSet())
	}

	return workflow.ConfigurationOptionsFromFlagset(fs)
}
