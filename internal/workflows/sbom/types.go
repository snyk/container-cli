package sbom

import "encoding/json"

type GetSbomForDepGraphRequest struct {
	DepGraphs []json.RawMessage `json:"depGraphs"`
	Subject   Subject           `json:"subject"`
}

type Subject struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GetSbomForDepGraphResult struct {
	Doc      []byte
	MIMEType string
}
