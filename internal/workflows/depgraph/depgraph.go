// © 2023-2024 Snyk Limited All rights reserved.
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

package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/container-cli/internal/common/workflows"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const internalErrorMessage = "an error occurred while running the underlying analysis needed to generate the depgraph"

type DepGraphWorkflow struct {
	workflows.BaseWorkflow
}

var Workflow = &DepGraphWorkflow{
	BaseWorkflow: workflows.BaseWorkflow{
		Name: "container depgraph",
		Flags: []flags.Flag{
			flags.FlagExcludeAppVulns,
		},
	},
}

func (d *DepGraphWorkflow) InitWorkflow(e workflow.Engine) error {
	_, err := e.Register(
		d.Identifier(),
		d.GetConfigurationOptionsFromFlagSet(),
		d.entrypoint,
	)
	return err
}

func (d *DepGraphWorkflow) TypeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(d.Identifier(), constants.DataTypeDepGraph)
}

var legacyCLIID = workflow.NewWorkflowIdentifier(constants.WorkflowIdentifierLegacyCli)

func (d *DepGraphWorkflow) entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	logger := ictx.GetEnhancedLogger()
	config := ictx.GetConfiguration()

	logger.Info().Msg("starting the depgraph workflow")

	baseCmdArgs := []string{"container", "test", "--print-graph", "--json"}
	cmdArgs := buildCliCommand(baseCmdArgs, d.Flags, config)

	logger.Info().Msgf("cli invocation args: %v", cmdArgs)
	config.Set(configuration.RAW_CMD_ARGS, cmdArgs)
	data, err := ictx.GetEngine().InvokeWithConfig(legacyCLIID, config)
	if err != nil {
		// TODO: maybe log the cli error instead of general error
		logger.Error().Err(err).Msg("failed to execute depgraph legacy workflow")
		return nil, extractLegacyCLIError(data, err)
	}

	if len(data) == 0 || data[0] == nil {
		return nil, mapInternalToUserError(
			logger, fmt.Errorf("empty depgraph legacy workflow response payload (payload: %s)", data),
			internalErrorMessage)
	}

	p, ok := data[0].GetPayload().([]byte)
	if !ok {
		return nil, mapInternalToUserError(logger, fmt.Errorf("could not convert payload, expected []byte, get %T",
			data[0].GetPayload()), internalErrorMessage)
	}

	depGraphList, err := extractDepGraphsFromCLIOutput(p, d.TypeIdentifier())
	if err != nil {
		return nil, mapInternalToUserError(logger, fmt.Errorf("could not extract depGraphs from CLI output: %w", err),
			internalErrorMessage)
	}

	logger.Info().Msgf("finished the depgraph workflow, number of depgraphs=%d", len(depGraphList))

	return depGraphList, nil
}

func buildCliCommand(baseCmdArgs []string, flags []flags.Flag, config configuration.Configuration) []string {
	var cmdArgs []string
	cmdArgs = append(cmdArgs, baseCmdArgs...)

	for _, flag := range flags {
		arg := flag.GetAsCLIArgument(config)
		cmdArgs = append(cmdArgs, arg)
	}

	cmdArgs = append(cmdArgs, config.GetString(constants.ContainerTargetArgName))
	return cmdArgs
}

// depGraphSeparator separates the depgraph from the target name and the rest.
// The DepGraph and the name are caught in a capturing group.
//
// The `(?s)` at the beginning enables multiline-matching.
var depGraphSeparator = regexp.MustCompile(`(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`)

func extractDepGraphsFromCLIOutput(output []byte, typeID workflow.Identifier) ([]workflow.Data, error) {
	if len(output) == 0 {
		return nil, errors.New("empty output")
	}

	matches := depGraphSeparator.FindAllSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("malformed CLI output, got 0 matches")
	}

	depGraphs := make([]workflow.Data, 0, len(matches))
	for _, match := range matches {
		data := workflow.NewData(typeID, constants.ContentTypeJSON, match[1])
		data.SetMetaData(constants.HeaderContentLocation, strings.TrimSpace(string(match[2])))
		depGraphs = append(depGraphs, data)
	}

	return depGraphs, nil
}

// legacyCLIJSONError is the error type returned by the legacy cli.
type legacyCLIJSONError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
}

// Error returns the LegacyCliJsonError error message.
func (e *legacyCLIJSONError) Error() string {
	return e.ErrorMsg
}

// extractLegacyCLIError extracts the error message from the legacy cli if possible.
func extractLegacyCLIError(data []workflow.Data, err error) error {
	// if there's no data, we can't extract anything.
	if len(data) == 0 {
		return err
	}

	// extract error from legacy cli if possible and wrap it in an error instance
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		bytes, ok := data[0].GetPayload().([]byte)
		if !ok {
			return fmt.Errorf("invalid payload type, want []byte, got %T", data[0].GetPayload())
		}

		var decodedError legacyCLIJSONError
		if json.Unmarshal(bytes, &decodedError) == nil {
			return &decodedError
		}
	}
	return err
}

func mapInternalToUserError(logger *zerolog.Logger, err error, userMessage string) error {
	logger.Err(err).Msg("failed to execute depgraph legacy workflow")
	return errors.New(userMessage)
}
