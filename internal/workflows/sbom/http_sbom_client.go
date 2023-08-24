package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/container-cli/internal/common/constants"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
)

const apiVersion = "2022-03-31~experimental"
const sbomForDepthGraphAPIEndpoint = "%s/hidden/orgs/%s/sbom?version=%s&format=%s"

type HttpSbomClientConfig struct {
	ApiUrl     string
	HttpClient HttpClient
	Logger     *zerolog.Logger
	ErrFactory *sbomerrors.SbomErrorFactory
}

type HttpSbomClient struct {
	apiUrl     string
	httpClient HttpClient
	logger     *zerolog.Logger
	errFactory *sbomerrors.SbomErrorFactory
}

func NewHttpSbomClient(conf HttpSbomClientConfig) *HttpSbomClient {
	return &HttpSbomClient{
		apiUrl:     conf.ApiUrl,
		httpClient: conf.HttpClient,
		logger:     conf.Logger,
		errFactory: conf.ErrFactory,
	}
}

func (c *HttpSbomClient) GetSbomForDepGraph(ctx context.Context, orgId, format string, req *GetSbomForDepGraphRequest) (*GetSbomForDepGraphResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to marshal sbom request: %w", err))
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf(sbomForDepthGraphAPIEndpoint, c.apiUrl, orgId, apiVersion, url.QueryEscape(format)),
		bytes.NewBuffer(body),
	)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to create http request: %w", err))
	}
	httpReq.Header.Add(constants.HeaderContentType, constants.ContentTypeJSON)

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to perform http call: %w", err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		io.Copy(io.Discard, res.Body)
		return nil, c.errorFromResponse(res, orgId)
	}

	doc, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to read response body: %w", err))
	}

	return &GetSbomForDepGraphResult{
		Doc:      doc,
		MIMEType: res.Header.Get(constants.HeaderContentType),
	}, nil
}

func (c *HttpSbomClient) errorFromResponse(res *http.Response, orgId string) error {
	err := fmt.Errorf("could not convert to SBOM (status: %s)", res.Status)
	switch res.StatusCode {
	case http.StatusBadRequest:
		return c.errFactory.NewBadRequestError(err)
	case http.StatusUnauthorized:
		return c.errFactory.NewUnauthorizedError(err)
	case http.StatusForbidden:
		return c.errFactory.NewForbiddenError(err, orgId)
	default:
		return c.errFactory.NewRemoteError(err)
	}
}
