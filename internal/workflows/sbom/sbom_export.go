package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	stderr "errors"
	"fmt"
	"github.com/snyk/container-cli/internal/common/constants"
	"github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"io"
	"log"
	"net/http"
	"net/url"
)

type (
	SBOMResult struct {
		Doc      []byte
		MIMEType string
	}
)

const apiVersion = "2022-03-31~experimental"

func DepGraphsToSBOM(
	client *http.Client,
	apiURL string,
	orgId string,
	depGraphs []json.RawMessage,
	imageName string,
	imageVersion string,
	format string,
	logger *log.Logger,
	errFactory *errors.SbomErrorFactory,
) (result *SBOMResult, err error) {
	payload, err := preparePayload(imageName, imageVersion, depGraphs)
	if err != nil {
		return nil, errFactory.NewInternalError(err)
	}

	req, err := buildRequest(apiURL, orgId, format, payload)
	if err != nil {
		return nil, errFactory.NewInternalError(err)
	}

	logger.Printf("Converting depgraphs remotely (url: %s)", req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("error while making request: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResponse(resp, orgId, errFactory)
	}

	defer resp.Body.Close()
	doc, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("could not read response body: %w", err))
	}

	return &SBOMResult{Doc: doc, MIMEType: resp.Header.Get(constants.HeaderContentType)}, nil
}

func preparePayload(imageName string, imageVersion string, depGraphs []json.RawMessage) ([]byte, error) {
	// todo: think of maybe extract this to the parse metadata
	// todo: should pass errFactory as well and
	if imageName == "" {
		return []byte{}, stderr.New("no subject defined for multiple depgraphs")
	}

	type subject struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type exportSbomRequestBody struct {
		DepGraphs []json.RawMessage `json:"depGraphs"`
		Subject   subject           `json:"subject"`
	}

	return json.Marshal(&exportSbomRequestBody{
		DepGraphs: depGraphs,
		Subject: subject{
			Name:    imageName,
			Version: imageVersion,
		},
	})
}

func buildRequest(apiURL string, orgId string, format string, payload []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgId, format),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Add(constants.HeaderContentType, constants.ContentTypeJSON)

	return req, nil
}

func buildURL(apiURL, orgID, format string) string {
	return fmt.Sprintf(
		"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
		apiURL, orgID, apiVersion, url.QueryEscape(format),
	)
}

func errorFromResponse(resp *http.Response, orgID string, errFactory *errors.SbomErrorFactory) error {
	err := fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errFactory.NewBadRequestError(err)
	case http.StatusUnauthorized:
		return errFactory.NewUnauthorizedError(err)
	case http.StatusForbidden:
		return errFactory.NewForbiddenError(err, orgID)
	default:
		return errFactory.NewRemoteError(err)
	}
}
