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

package sbom

import (
	"context"
	"slices"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	containerdepgraph "github.com/snyk/container-cli/internal/workflows/depgraph"
	sbomconstants "github.com/snyk/container-cli/internal/workflows/sbom/constants"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Workflow represents the SBOM workflow
type Workflow struct {
	workflows.BaseWorkflow
	depGraph   *containerdepgraph.DepGraphWorkflow
	sbomClient SbomClient
	errFactory *sbomerrors.SbomErrorFactory
}

// NewWorkflow creates a new SBOM workflow value
func NewWorkflow(sbomClient SbomClient, errFactory *sbomerrors.SbomErrorFactory) *Workflow {
	return &Workflow{
		BaseWorkflow: workflows.BaseWorkflow{
			Name: "container sbom",
			Flags: []flags.Flag{
				flags.FlagSbomFormat,
				flags.FlagExcludeAppVulns,
				flags.FlagPlatform,
			},
		},
		depGraph:   containerdepgraph.Workflow,
		sbomClient: sbomClient,
		errFactory: errFactory,
	}
}

// Init registers the workflow for the provided engine
func (w *Workflow) Init(e workflow.Engine) error {
	_, err := e.Register(
		w.Identifier(),
		w.GetConfigurationOptionsFromFlagSet(),
		w.entrypoint,
	)
	return err
}

func (w *Workflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	var logger = ictx.GetEnhancedLogger()
	logger.Info().Msg("starting the sbom workflow")

	var config = ictx.GetConfiguration()

	logger.Debug().Msg("getting the sbom format")
	var format = flags.FlagSbomFormat.GetFlagValue(config)
	if err := validateSBOMFormat(format, sbomconstants.SbomValidFormats, w.errFactory); err != nil {
		return nil, err
	}

	logger.Debug().Msg("getting the platform")
	var platform = flags.FlagPlatform.GetFlagValue(config)
	if err := validatePlatform(platform, sbomconstants.ValidPlatforms, w.errFactory); err != nil {
		return nil, err
	}

	logger.Debug().Msg("getting preferred organization id")
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, w.errFactory.NewEmptyOrgError()
	}

	logger.Debug().Msg("invoking depgraph workflow")
	depGraphs, err := ictx.GetEngine().InvokeWithConfig(w.depGraph.Identifier(), config.Clone())
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	imageAndVersion := config.GetString(constants.ContainerTargetArgName)
	imageName, imageVersion, err := depGraphMetadata(imageAndVersion)
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	logger.Debug().Msgf("image name: '%v', image version: '%v'", imageName, imageVersion)
	depGraphsBytes, err := parseDepGraph(depGraphs)
	if err != nil {
		return nil, w.errFactory.NewDepGraphWorkflowError(err)
	}

	sbomResult, err := w.sbomClient.GetSbomForDepGraph(
		context.Background(),
		orgID,
		format,
		platform,
		&GetSbomForDepGraphRequest{
			DepGraphs: depGraphsBytes,
			Subject: Subject{
				Name:    imageName,
				Version: imageVersion,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	logger.Info().Msg("successfully generated SBOM document")
	return []workflow.Data{
		workflow.NewDataFromInput(nil, w.typeIdentifier(), sbomResult.MIMEType, sbomResult.Doc),
	}, nil
}

func (w *Workflow) typeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(w.Identifier(), constants.DataTypeSbom)
}

func validateSBOMFormat(candidate string, sbomFormats []string, errFactory *sbomerrors.SbomErrorFactory) error {
	if candidate == "" {
		return errFactory.NewEmptySbomFormatError(sbomFormats)
	}

	if !slices.Contains(sbomFormats, candidate) {
		return errFactory.NewInvalidSbomFormatError(candidate, sbomFormats)
	}

	return nil
}

func validatePlatform(candidate string, platforms []string, errFactory *sbomerrors.SbomErrorFactory) error {
	if candidate != "" && !slices.Contains(platforms, candidate) {
		return errFactory.NewInvalidPlatformError(candidate, platforms)
	}
	return nil
}
