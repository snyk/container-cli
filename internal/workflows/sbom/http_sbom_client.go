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

// HTTPSbomClientConfig represents the configuration for HTTPSbomClient
type HTTPSbomClientConfig struct {
	APIHost    string
	Client     *http.Client
	Logger     *zerolog.Logger
	ErrFactory *sbomerrors.SbomErrorFactory
}

// HTTPSbomClient represents the HTTP client for the SBOM API
type HTTPSbomClient struct {
	apiHost    string
	client     *http.Client
	logger     *zerolog.Logger
	errFactory *sbomerrors.SbomErrorFactory
}

// NewHTTPSbomClient creates a new HTTPSbomClient value
func NewHTTPSbomClient(conf HTTPSbomClientConfig) *HTTPSbomClient {
	return &HTTPSbomClient{
		apiHost:    conf.APIHost,
		client:     conf.Client,
		logger:     conf.Logger,
		errFactory: conf.ErrFactory,
	}
}

// GetSbomForDepGraph retrieves the SBOM for a depgraph
func (c *HTTPSbomClient) GetSbomForDepGraph(
	ctx context.Context,
	orgID, format, platform string,
	req *GetSbomForDepGraphRequest,
) (*GetSbomForDepGraphResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to marshal sbom request: %w", err))
	}

	urlWithParams := fmt.Sprintf(
		"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
		c.apiHost,
		orgID,
		"2022-03-31~experimental",
		url.QueryEscape(format),
	)
	if platform != "" {
		urlWithParams += fmt.Sprintf("&platform=%s", url.QueryEscape(platform))
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		urlWithParams,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to create http request: %w", err))
	}
	httpReq.Header.Add(constants.HeaderContentType, constants.ContentTypeJSON)

	res, err := c.client.Do(httpReq)
	if err != nil {
		return nil, c.errFactory.NewInternalError(fmt.Errorf("failed to perform http call: %w", err))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		_, err = io.Copy(io.Discard, res.Body)
		if err != nil {
			c.logger.Error().Err(err).Msg("failed to discard the body for unsuccessful response")
		}
		return nil, c.errorFromResponse(res, orgID)
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

func (c *HTTPSbomClient) errorFromResponse(res *http.Response, orgID string) error {
	err := fmt.Errorf("could not convert to SBOM (status: %s)", res.Status)
	switch res.StatusCode {
	case http.StatusBadRequest:
		return c.errFactory.NewBadRequestError(err)
	case http.StatusUnauthorized:
		return c.errFactory.NewUnauthorizedError(err)
	case http.StatusForbidden:
		return c.errFactory.NewForbiddenError(err, orgID)
	default:
		return c.errFactory.NewRemoteError(err)
	}
}
