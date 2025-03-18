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

package container

import (
	"fmt"

	"github.com/snyk/container-cli/internal/workflows/depgraph"
	"github.com/snyk/container-cli/internal/workflows/sbom"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Init initialises all container cli workflows.
func Init(e workflow.Engine) error {
	if err := initSbomWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container sbom workflow: %w", err)
	}

	if err := depgraph.Workflow.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialise container depgraph workflow: %w", err)
	}

	return nil
}

func initSbomWorkflow(e workflow.Engine) error {
	errFactory := sbomerrors.NewSbomErrorFactory(e.GetLogger())

	sbomWorkflow := sbom.NewWorkflow(sbom.NewHTTPSbomClient(sbom.HTTPSbomClientConfig{
		APIHost:    e.GetConfiguration().GetString(configuration.API_URL),
		Client:     e.GetNetworkAccess().GetHttpClient(),
		Logger:     e.GetLogger(),
		ErrFactory: errFactory,
	}), errFactory)

	return sbomWorkflow.Init(e)
}
