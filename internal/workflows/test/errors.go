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
	"strings"
)

// SkippedFilesError is returned when the File Upload API silently dropped one
// or more ScanResult files. Proceeding against an incomplete revision would
// produce a partial test with no protocol-level indication of what was
// missing, so the dragonfly flow aborts before calling StartTest.
type SkippedFilesError struct {
	Paths []string
}

func (e *SkippedFilesError) Error() string {
	return fmt.Sprintf("file upload skipped %d file(s): %s", len(e.Paths), strings.Join(e.Paths, ", "))
}

// ComponentFailureError is returned when one or more per-component tests
// errored on the platform side. container-engine reports per-component
// failures via Component.Success=false; the CLI escalates any such failure
// to a total test failure so the customer sees an all-or-nothing result.
// Details carries the platform-supplied error detail strings for diagnostic
// surfacing.
type ComponentFailureError struct {
	Details []string
}

func (e *ComponentFailureError) Error() string {
	return fmt.Sprintf("test failed for %d component(s): %s", len(e.Details), strings.Join(e.Details, ", "))
}

// IncompleteFindingsError is returned when the FindingData pagination did
// not drain to complete=true. A partial findings list would silently
// underreport vulnerabilities to the customer. Received records how many
// findings were drained before the abort so the operator can correlate.
type IncompleteFindingsError struct {
	Received int
}

func (e *IncompleteFindingsError) Error() string {
	return fmt.Sprintf("findings pagination did not complete (%d findings received before abort)", e.Received)
}
