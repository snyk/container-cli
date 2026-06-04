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

// SkippedFilesError is returned when File Upload API silently drops one or more ScanResult files.
// Proceeding against an incomplete revision would produce a partial test result with no indication
// of what was missing, so we abort before calling StartTest.
type SkippedFilesError struct {
	Paths []string
}

func (e *SkippedFilesError) Error() string {
	return fmt.Sprintf(
		"upload aborted: %d ScanResult file(s) exceeded size or path limits and were skipped: %s",
		len(e.Paths),
		strings.Join(e.Paths, ", "),
	)
}

// ComponentFailureError is returned when one or more per-ScanResult components failed on the
// server side. We fail closed: a partial result is more dangerous than no result because the
// customer may proceed with a false sense of security.
type ComponentFailureError struct {
	Errors []string
}

func (e *ComponentFailureError) Error() string {
	return fmt.Sprintf(
		"test failed: %d component(s) could not be analysed: %s",
		len(e.Errors),
		strings.Join(e.Errors, "; "),
	)
}

// IncompleteFindingsError is returned when the findings poll loop exits before completion
// (e.g. context deadline). Rendering a truncated finding stream would silently hide vulns.
type IncompleteFindingsError struct {
	Received int
}

func (e *IncompleteFindingsError) Error() string {
	return fmt.Sprintf(
		"test timed out before all findings were received (received %d so far); re-run or increase timeout",
		e.Received,
	)
}
