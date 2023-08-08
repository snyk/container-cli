package sbom

import (
	"encoding/json"
	"fmt"
	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func DepGraphMetadata(imgName string) (name, version string, err error) {
	// we currently don't have a way of extracting the clean image name & potentially a digest from
	// the DepGraph output, so we use what's been passed on the command line.
	ref, err := reference.Parse(imgName)
	if err != nil {
		return "", "", fmt.Errorf("could not parse container name: %w", err)
	}

	// sadly the reference library doesn't export these interfaces...
	type named interface{ Name() string }
	type digested interface{ Digest() digest.Digest }
	type tagged interface{ Tag() string }
	// shouldn't happen :-)
	n, ok := ref.(named)
	if !ok {
		return "", "", fmt.Errorf("image %q does not contain a name", imgName)
	}

	switch s := ref.(type) {
	case digested:
		return n.Name(), s.Digest().String(), nil
	case tagged:
		return n.Name(), s.Tag(), nil
	default:
		return n.Name(), "", nil
	}
}

func ParseDepGraph(depGraphs []workflow.Data) ([]json.RawMessage, error) {
	depGraphsBytes := make([]json.RawMessage, 0, len(depGraphs))
	for _, depGraph := range depGraphs {
		// not sure if this can ever happen, but better be sure.
		if depGraph.GetPayload() == nil {
			continue
		}

		depGraphBytes, ok := depGraph.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", depGraph.GetPayload())
		}
		depGraphsBytes = append(depGraphsBytes, depGraphBytes)
	}

	return depGraphsBytes, nil
}
