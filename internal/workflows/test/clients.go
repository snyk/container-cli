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

package test

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// defaultPollInterval is how often the testapi client polls for completion
// once StartTest returns a handle. 5s matches what os-flows uses; the testapi
// client itself owns retry-with-backoff semantics on top of this base.
const defaultPollInterval = 5 * time.Second

// setupFileUploadClient builds the File Upload API client from the framework's
// authenticated HTTP client + per-org configuration. The blob store uses a
// distinct URL base and retry semantics from the Test API, so the two clients
// are constructed separately.
func setupFileUploadClient(ictx workflow.InvocationContext, orgID uuid.UUID) fileupload.Client {
	cfg := ictx.GetConfiguration()
	return fileupload.NewClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		fileupload.Config{
			BaseURL: cfg.GetString(configuration.API_URL),
			OrgID:   orgID,
		},
		fileupload.WithLogger(ictx.GetEnhancedLogger()),
	)
}

// setupTestClient builds the Test API client that talks to test-api-shim at
// /rest/. Polling-interval bookkeeping, transient-error retry, and context
// cancellation live inside the testapi client; the workflow simply calls
// StartTest and Wait.
func setupTestClient(ictx workflow.InvocationContext) (testapi.TestClient, error) {
	cfg := ictx.GetConfiguration()
	apiURL := cfg.GetString(configuration.API_URL)

	client, err := testapi.NewTestClient(
		apiURL+"/rest/",
		testapi.WithPollInterval(defaultPollInterval),
		testapi.WithCustomHTTPClient(ictx.GetNetworkAccess().GetHttpClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating test client: %w", err)
	}
	return client, nil
}
