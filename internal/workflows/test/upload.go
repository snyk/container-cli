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

// containerAnalysisContentType is the ContentType that routes the shim's assembler
// to the container assembler (WP6). It is distinct from Sbom/Source because container
// analysis is semantically different: a set of ScanResult[] files produced by
// snyk-docker-plugin, not a dep-graph SBOM or source tree.
const containerAnalysisContentType testapi.UploadResourceContentType = "container_analysis"

// newContainerUploadResource wraps a File Upload revision ID into the TestResourceCreateItem
// shape that test-api-shim expects. ScmContext is nil because container images are OCI
// artifacts, not SCM commits.
func newContainerUploadResource(revisionID string) (testapi.TestResourceCreateItem, error) {
	uploadResource := testapi.UploadResource{
		ContentType:  containerAnalysisContentType,
		FilePatterns: []string{},
		RevisionId:   revisionID,
		Type:         testapi.Upload,
		ScmContext:   nil,
	}

	var resourceVariant testapi.BaseResourceVariantCreateItem
	if err := resourceVariant.FromUploadResource(uploadResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create resource variant: %w", err)
	}

	baseResource := testapi.BaseResourceCreateItem{
		Resource: resourceVariant,
		Type:     testapi.BaseResourceCreateItemTypeBase,
	}

	var testResource testapi.TestResourceCreateItem
	if err := testResource.FromBaseResourceCreateItem(baseResource); err != nil {
		return testapi.TestResourceCreateItem{}, fmt.Errorf("failed to create test resource: %w", err)
	}

	return testResource, nil
}
