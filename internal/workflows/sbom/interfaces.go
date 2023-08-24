package sbom

import (
	"context"
	"net/http"
)

//go:generate mockgen -source=./interfaces.go -destination=./interfaces_mocks.go -package=sbom

type SbomClient interface {
	GetSbomForDepGraph(ctx context.Context, orgId, format string, req *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error)
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}
