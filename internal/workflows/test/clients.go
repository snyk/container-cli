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

const defaultPollInterval = 5 * time.Second

// setupFileUploadClient constructs the File Upload API client from the framework's authenticated
// HTTP client. The blob store uses a different URL base and different reliability semantics than
// the Test API, so the two clients are kept separate.
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

// setupTestClient constructs the Test API client that talks to test-api-shim at /rest/.
// All polling interval management, retry on transient errors, and context-cancellation handling
// are inside the GAF testapi client — the workflow just calls Wait.
func setupTestClient(ictx workflow.InvocationContext) (testapi.TestClient, error) {
	cfg := ictx.GetConfiguration()
	apiURL := cfg.GetString(configuration.API_URL)

	client, err := testapi.NewTestClient(
		apiURL+"/rest/",
		testapi.WithPollInterval(defaultPollInterval),
		testapi.WithCustomHTTPClient(ictx.GetNetworkAccess().GetHttpClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create test client: %w", err)
	}
	return client, nil
}
