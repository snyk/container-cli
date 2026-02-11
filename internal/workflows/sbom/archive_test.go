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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsArchiveInput(t *testing.T) {
	type test struct {
		input    string
		expected bool
	}

	tests := map[string]test{
		// Archive prefixes
		"docker-archive with absolute path": {"docker-archive:/path/to/image.tar", true},
		"docker-archive with filename":      {"docker-archive:image.tar", true},
		"docker-archive with relative path": {"docker-archive:relative/path/image.tar", true},
		"oci-archive with absolute path":    {"oci-archive:/path/to/image.tar", true},
		"oci-archive with filename":         {"oci-archive:image.tar", true},
		"kaniko-archive with absolute path": {"kaniko-archive:/path/to/image.tar", true},
		"kaniko-archive with filename":      {"kaniko-archive:image.tar", true},

		// Bare .tar files
		"absolute path .tar": {"/path/to/image.tar", true},
		"filename .tar":      {"image.tar", true},
		"relative path .tar": {"./relative/image.tar", true},

		// Non-archive inputs
		"image with tag":          {"nginx:latest", false},
		"image with version":      {"alpine:3.17.0", false},
		"registry image with tag": {"registry.example.com/repo:tag", false},
		"bare image name":         {"ubuntu", false},
		"empty string":            {"", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := isArchiveInput(tc.input)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestArchiveMetadata(t *testing.T) {
	type test struct {
		input        string
		expectedName string
		expectedVer  string
	}

	tests := map[string]test{
		// docker-archive prefix — name retains .tar extension (matches v1 behavior)
		"docker-archive absolute path": {"docker-archive:/var/tmp/nginx.tar", "nginx.tar", ""},
		"docker-archive nested path":   {"docker-archive:/path/to/my-image.tar", "my-image.tar", ""},
		"docker-archive filename only": {"docker-archive:image.tar", "image.tar", ""},

		// oci-archive prefix
		"oci-archive absolute path": {"oci-archive:/path/to/image.tar", "image.tar", ""},
		"oci-archive relative path": {"oci-archive:relative/path/app.tar", "app.tar", ""},

		// kaniko-archive prefix
		"kaniko-archive absolute path": {"kaniko-archive:/path/to/image.tar", "image.tar", ""},
		"kaniko-archive filename only": {"kaniko-archive:build-output.tar", "build-output.tar", ""},

		// Bare .tar files
		"bare absolute path": {"/path/to/image.tar", "image.tar", ""},
		"bare filename":      {"image.tar", "image.tar", ""},
		"bare relative path": {"./relative/image.tar", "image.tar", ""},

		// Non-.tar extension with prefix (e.g. .tar.gz)
		"docker-archive tar.gz": {"docker-archive:/path/to/image.tar.gz", "image.tar.gz", ""},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			name, version := archiveMetadata(tc.input)
			require.Equal(t, tc.expectedName, name)
			require.Equal(t, tc.expectedVer, version)
		})
	}
}
