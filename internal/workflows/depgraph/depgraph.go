package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

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
			flags.FlagDebug,
			flags.FlagAppVulns,
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
	// TODO: this is only tested through the integration test. We might want to add a unit-test for
	// this :)
	logger := ictx.GetLogger()
	logger.SetPrefix(d.Name)
	config := ictx.GetConfiguration()

	logger.Println("starting the depgraph workflow")

	cmdArgs := buildCliCommand(d.Flags, config)

	logger.Printf("cli invocation args: %v", cmdArgs)

	config.Set(configuration.RAW_CMD_ARGS, cmdArgs)
	data, err := ictx.GetEngine().InvokeWithConfig(legacyCLIID, config)
	if err != nil {
		logger.Printf(fmt.Errorf("failed to execute depgraph legacy workflow: %w", err).Error())
		return nil, extractLegacyCLIError(err, data)
	}

	if data[0] == nil {
		return nil, mapInternalToUserError(logger, errors.New("empty depgraph legacy workflow response payload"), internalErrorMessage)
	}

	p, ok := data[0].GetPayload().([]byte)
	if !ok {
		return nil, mapInternalToUserError(logger, fmt.Errorf("could not convert payload, expected []byte, get %T", data[0].GetPayload()), internalErrorMessage)
	}

	depGraphList, err := extractDepGraphsFromCLIOutput(p, d.TypeIdentifier())
	if err != nil {
		return nil, mapInternalToUserError(logger, fmt.Errorf("could not extract depGraphs from CLI output: %w", err), internalErrorMessage)
	}

	logger.Printf("finished the depgraph workflow, number of depgraphs=%d", len(depGraphList))

	return depGraphList, nil
}

func buildCliCommand(flags []flags.Flag, config configuration.Configuration) []string {
	cmdArgs := []string{"container", "test", "--print-graph", "--json"}
	for _, flag := range flags {
		arg := flag.GetAsCLIArgument(config)
		cmdArgs = append(cmdArgs, arg)
	}

	cmdArgs = append(cmdArgs, config.GetString(constants.ContainerTargetArgName))
	return cmdArgs
}

// TODO: all the code until EOF could also be taken from Link's implementations / could be
// shared.

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
	depGraphs := make([]workflow.Data, 0, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			return nil, fmt.Errorf("malformed CLI output, got %v matches", len(match))
		}

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
func extractLegacyCLIError(input error, data []workflow.Data) error {
	// if there's no data, we can't extract anything.
	if len(data) == 0 {
		return input
	}

	// extract error from legacy cli if possible and wrap it in an error instance
	var exitErr *exec.ExitError
	if errors.As(input, &exitErr) {
		bytes, ok := data[0].GetPayload().([]byte)
		if !ok {
			return nil
		}

		var decodedError legacyCLIJSONError
		if json.Unmarshal(bytes, &decodedError) == nil {
			return &decodedError
		}
	}
	return input
}

func mapInternalToUserError(logger *log.Logger, err error, userMessage string) error {
	logger.Printf(err.Error())
	return errors.New(userMessage)
}
