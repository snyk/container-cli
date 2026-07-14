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

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With no policy flags set, BuildLocalPolicy returns (nil, nil) so the platform
// default-policy resolver takes over — matches legacy "no flag, no threshold".
func TestBuildLocalPolicy_ReturnsNilWhenNoFlagsSet(t *testing.T) {
	cfg := configuration.NewInMemory()
	got, err := BuildLocalPolicy(cfg)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// --severity-threshold flows into LocalPolicy.SeverityThreshold.
func TestBuildLocalPolicy_PopulatesSeverityThreshold(t *testing.T) {
	cfg := configuration.NewInMemory()
	cfg.Set("severity-threshold", "high")

	got, err := BuildLocalPolicy(cfg)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotNil(t, got.SeverityThreshold)
	assert.Equal(t, testapi.SeverityHigh, *got.SeverityThreshold)
	assert.Nil(t, got.FailOnUpgradable)
}

// --fail-on=upgradable and --fail-on=all both flip FailOnUpgradable to true.
func TestBuildLocalPolicy_PopulatesFailOnUpgradable(t *testing.T) {
	for _, val := range []string{"upgradable", "all", "UPGRADABLE"} {
		t.Run(val, func(t *testing.T) {
			cfg := configuration.NewInMemory()
			cfg.Set("fail-on", val)

			got, err := BuildLocalPolicy(cfg)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got.FailOnUpgradable)
			assert.True(t, *got.FailOnUpgradable)
		})
	}
}

// An unsupported --fail-on value surfaces a clear error rather than silently ignoring.
func TestBuildLocalPolicy_RejectsUnsupportedFailOnValue(t *testing.T) {
	cfg := configuration.NewInMemory()
	cfg.Set("fail-on", "patchable")

	got, err := BuildLocalPolicy(cfg)
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Contains(t, err.Error(), "patchable")
}

// BuildTestConfiguration wraps the policy and always sets ScanConfig.Container
// so the platform routes the test to the container assembler.
func TestBuildTestConfiguration_AlwaysSetsContainerScanConfig(t *testing.T) {
	cfg := BuildTestConfiguration(nil)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.ScanConfig)
	assert.NotNil(t, cfg.ScanConfig.Container)
	assert.Nil(t, cfg.LocalPolicy)
}

// When a LocalPolicy is provided, it flows through onto the TestConfiguration verbatim.
func TestBuildTestConfiguration_CarriesLocalPolicy(t *testing.T) {
	sev := testapi.SeverityMedium
	policy := &testapi.LocalPolicy{SeverityThreshold: &sev}

	cfg := BuildTestConfiguration(policy)
	require.NotNil(t, cfg.LocalPolicy)
	assert.Same(t, policy, cfg.LocalPolicy)
}
