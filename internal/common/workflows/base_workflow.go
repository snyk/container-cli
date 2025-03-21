// © 2023-2025 Snyk Limited All rights reserved.
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
