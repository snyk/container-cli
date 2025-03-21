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

package sbom

import (
	"encoding/json"
	"fmt"

	"github.com/docker/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func depGraphMetadata(imgName string) (name, version string, err error) {
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

func parseDepGraph(depGraphs []workflow.Data) ([]json.RawMessage, error) {
	depGraphsBytes := make([]json.RawMessage, 0, len(depGraphs))
	for _, depGraph := range depGraphs {
		// not sure if this can ever happen, but better be sure.
		if depGraph.GetPayload() == nil {
			continue
		}

		depGraphBytes, ok := depGraph.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type, want []byte, got %T", depGraph.GetPayload())
		}
		depGraphsBytes = append(depGraphsBytes, depGraphBytes)
	}

	return depGraphsBytes, nil
}
