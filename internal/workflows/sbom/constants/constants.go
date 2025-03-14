// © 2023-2025 Snyk Limited All rights reserved.
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

package constants

var SbomValidFormats = []string{
	"cyclonedx1.4+json",
	"cyclonedx1.4+xml",
	"cyclonedx1.5+json",
	"cyclonedx1.5+xml",
	"cyclonedx1.6+json",
	"cyclonedx1.6+xml",
	"spdx2.3+json",
}

var ValidPlatforms = []string{
	"linux/amd64",
	"linux/arm64",
	"linux/riscv64",
	"linux/ppc64le",
	"linux/s390x",
	"linux/386",
	"linux/arm/v7",
	"linux/arm/v6",
}
