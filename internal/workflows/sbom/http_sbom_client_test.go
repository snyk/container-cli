// © 2023 Snyk Limited All rights reserved.
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	zlog "github.com/rs/zerolog/log"
	"github.com/snyk/container-cli/internal/common/constants"
	sbomconstants "github.com/snyk/container-cli/internal/workflows/sbom/constants"
	sbomerrors "github.com/snyk/container-cli/internal/workflows/sbom/errors"
	"github.com/stretchr/testify/require"
)

var (
	version = "2022-03-31~experimental"
	orgID   = "aaacbb21-19b4-44f4-8483-d03746156f6b"
	format  = sbomconstants.SbomValidFormats[0]
)

func Test_GetSbomForDepGraph_GivenNoError_ShouldReturnSbom(t *testing.T) {
	depGraphBytes, err := os.ReadFile("testdata/sbom_request_depgraph.json")
	require.NoError(t, err)

	req := GetSbomForDepGraphRequest{
		DepGraphs: []json.RawMessage{depGraphBytes},
		Subject: Subject{
			Name:    "alpine",
			Version: "3.17.0",
		},
	}

	expectedReqBody, err := json.Marshal(&req)
	require.NoError(t, err)

	expectedResBody, err := os.ReadFile("testdata/sbom_result_doc.json")
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(
			t,
			r.URL.String(),
			fmt.Sprintf("/hidden/orgs/%s/sbom?version=%s&format=%s", orgID, version, url.QueryEscape(format)),
		)

		body, handlerErr := io.ReadAll(r.Body)
		require.NoError(t, handlerErr)

		require.Equal(t, expectedReqBody, body)

		w.Header().Add(constants.HeaderContentType, constants.ContentTypeJSON)

		_, handlerErr = w.Write(expectedResBody)
		require.NoError(t, handlerErr)
	}))
	defer server.Close()

	client := NewHTTPSbomClient(HTTPSbomClientConfig{
		APIHost:    server.URL,
		Client:     http.DefaultClient,
		Logger:     &zlog.Logger,
		ErrFactory: sbomerrors.NewSbomErrorFactory(&zlog.Logger),
	})

	res, err := client.GetSbomForDepGraph(context.Background(), orgID, format, &req)
	require.NoError(t, err)

	require.Equal(t, &GetSbomForDepGraphResult{
		Doc:      expectedResBody,
		MIMEType: constants.ContentTypeJSON,
	}, res)
}
