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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// defaultPollInterval is the cadence the test client polls for completion.
// Locking it in here prevents accidental tuning that would change the platform
// load profile — any change should be deliberate and reviewed.
func TestDefaultPollInterval_IsFiveSeconds(t *testing.T) {
	assert.Equal(t, 5*time.Second, defaultPollInterval)
}
