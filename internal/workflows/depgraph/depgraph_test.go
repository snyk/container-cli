package depgraph //nolint:testpackage // we want to use private functions.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/common/workflows"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Depgraph_extractLegacyCLIError_extractError(t *testing.T) {
	expectedMsgJSON := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	inputError := &exec.ExitError{}
	data := workflow.NewData(Workflow.TypeIdentifier(), "application/json", []byte(expectedMsgJSON))

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, "Hello Error", outputError.Error())

	var legacyErr *legacyCLIJSONError
	assert.ErrorAs(t, outputError, &legacyErr)
}

func Test_Depgraph_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(Workflow.TypeIdentifier(), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, inputError.Error(), outputError.Error())
}

func Test_Depgraph_InitDepGraphWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := Workflow.InitWorkflow(engine)
	assert.Nil(t, err)

	flagBool := config.Get("debug")
	assert.Equal(t, false, flagBool)
}

func TestExtractDepGraphsFromCLIOutput(t *testing.T) {
	type depGraph struct {
		name string
		file string
	}
	type testCase struct {
		cliOutputFile string
		graphs        []depGraph
	}

	testCases := []testCase{{
		cliOutputFile: "testdata/single_depgraph_output.txt",
		graphs: []depGraph{{
			name: "package-lock.json",
			file: "testdata/single_depgraph.json",
		}},
	}, {
		cliOutputFile: "testdata/multi_depgraph_output.txt",
		graphs: []depGraph{{
			name: "docker-image|snyk/kubernetes-scanner",
			file: "testdata/multi_depgraph_1.json",
		}, {
			name: "docker-image|snyk/kubernetes-scanner:/kubernetes-scanner",
			file: "testdata/multi_depgraph_2.json",
		}},
	}}

	d := DepGraphWorkflow{
		workflows.BaseWorkflow{
			Name:  "whatever",
			Flags: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.cliOutputFile, func(t *testing.T) {
			output, err := os.ReadFile(tc.cliOutputFile)
			require.NoError(t, err)

			data, err := extractDepGraphsFromCLIOutput(output, d.TypeIdentifier())
			require.NoError(t, err)

			require.Len(t, data, len(tc.graphs))
			for i, graph := range tc.graphs {
				testDepGraphFromFile(t, graph.name, graph.file, data[i])
			}
		})
	}
}

func testDepGraphFromFile(t *testing.T, dgName, fileName string, actual workflow.Data) {
	t.Helper()
	content, err := os.ReadFile(fileName)
	require.NoError(t, err)

	var expectedDG map[string]interface{}
	err = json.Unmarshal(content, &expectedDG)
	require.NoError(t, err)

	require.Equal(t, constants.ContentTypeJSON, actual.GetContentType())
	require.Equal(t, dgName, actual.GetContentLocation())

	payload, ok := actual.GetPayload().([]byte)
	if !ok {
		t.Fatalf("payload is not []byte: %T", actual.GetPayload())
	}

	var actualDG map[string]interface{}
	err = json.Unmarshal(payload, &actualDG)
	require.NoError(t, err)
	require.Equal(t, expectedDG, actualDG)
}
