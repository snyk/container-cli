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
	"path/filepath"
	"strings"
)

// archivePrefixes defines the supported archive URI prefixes.
// These must stay in sync with snyk-docker-plugin/lib/image-type.ts (getImageType).
var archivePrefixes = []string{
	"docker-archive:",
	"oci-archive:",
	"kaniko-archive:",
}

// isArchiveInput returns true if the input is an archive reference,
// either prefixed (docker-archive:, oci-archive:, kaniko-archive:) or ending in .tar.
func isArchiveInput(input string) bool {
	for _, prefix := range archivePrefixes {
		if strings.HasPrefix(input, prefix) {
			return true
		}
	}
	return strings.HasSuffix(input, ".tar")
}

// archiveMetadata extracts a meaningful name and version from an archive input.
// For archive inputs, the name is derived from the file basename (including the
// .tar extension), and the version is left empty. This is consistent with how
// snyk-docker-plugin derives image identifiers and existing v1 behavior.
func archiveMetadata(input string) (name, version string) {
	path := input

	// Strip known archive prefixes to get the file path.
	for _, prefix := range archivePrefixes {
		if strings.HasPrefix(input, prefix) {
			path = input[len(prefix):]
			break
		}
	}

	name = filepath.Base(path)
	return name, ""
}
