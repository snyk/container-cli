package sbom

import (
	"context"
	"net/http"
)

//go:generate mockgen -source=./interfaces.go -destination=./interfaces_mocks.go -package=sbom

// SbomClient provides SBOM generation operations
type SbomClient interface {
	GetSbomForDepGraph(context.Context, string, string, *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error)
}

// HTTPClient provides HTTP client operations
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
