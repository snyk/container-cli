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

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// containerAnalysisContentType is the test-api-shim assembler discriminator
// for container scans. It is distinct from sbom/source because container
// analysis is semantically different — a set of ScanResult[] files produced
// by snyk-docker-plugin, not a dep-graph SBOM or a source tree. The GAF
// testapi enum currently only enumerates "sbom" and "source"; the shim adds
// "container_analysis" out-of-band (WP6) and the string cast forwards the
// value pending the GAF enum extension.
const containerAnalysisContentType testapi.UploadResourceContentType = "container_analysis"

// newContainerUploadResource wraps a File Upload revision id in the
// TestResourceCreateItem shape that test-api-shim expects for a container
// test. ScmContext is nil because container images are OCI artifacts, not
// SCM commits.
func newContainerUploadResource(revisionID string) (testapi.TestResourceCreateItem, error) {
	var item testapi.TestResourceCreateItem

	uploadResource := testapi.UploadResource{
		ContentType:  containerAnalysisContentType,
		FilePatterns: []testapi.String256{},
		RevisionId:   revisionID,
		Type:         testapi.Upload,
	}

	var variant testapi.BaseResourceVariantCreateItem
	if err := variant.FromUploadResource(uploadResource); err != nil {
		return item, fmt.Errorf("wrapping UploadResource: %w", err)
	}

	base := testapi.BaseResourceCreateItem{
		Resource: variant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	if err := item.FromBaseResourceCreateItem(base); err != nil {
		return item, fmt.Errorf("wrapping BaseResourceCreateItem: %w", err)
	}
	return item, nil
}
