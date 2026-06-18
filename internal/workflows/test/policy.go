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

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/container-cli/internal/common/flags"
)

// BuildLocalPolicy assembles a testapi.LocalPolicy from the container test
// flags. Returns (nil, nil) when no policy flag is set so the platform's
// default-policy resolver can take over — this matches cli-extension-os-flows'
// CreateLocalPolicy semantics and the legacy "no flag means no threshold"
// behaviour that pre-Dragonfly snyk container test relied on.
func BuildLocalPolicy(cfg configuration.Configuration) (*testapi.LocalPolicy, error) {
	severityThreshold := severityThresholdFromConfig(cfg)
	failOnUpgradable, err := failOnFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	if severityThreshold == nil && failOnUpgradable == nil {
		return nil, nil //nolint:nilnil
	}
	return &testapi.LocalPolicy{
		SeverityThreshold: severityThreshold,
		FailOnUpgradable:  failOnUpgradable,
	}, nil
}

// BuildTestConfiguration wraps a LocalPolicy in the TestConfiguration shape
// test-api-shim expects, with ScanConfig.Container set so the platform routes
// the test to the container assembler.
func BuildTestConfiguration(localPolicy *testapi.LocalPolicy) *testapi.TestConfiguration {
	return &testapi.TestConfiguration{
		LocalPolicy: localPolicy,
		ScanConfig: &testapi.ScanConfiguration{
			Container: &testapi.ContainerScanConfiguration{},
		},
	}
}

func severityThresholdFromConfig(cfg configuration.Configuration) *testapi.Severity {
	v := flags.FlagSeverityThreshold.GetFlagValue(cfg)
	if v == "" {
		return nil
	}
	s := testapi.Severity(v)
	return &s
}

func failOnFromConfig(cfg configuration.Configuration) (*bool, error) {
	v := flags.FlagFailOn.GetFlagValue(cfg)
	if v == "" {
		return nil, nil //nolint:nilnil
	}
	switch strings.ToLower(v) {
	case "upgradable", "all":
		t := true
		return &t, nil
	default:
		return nil, fmt.Errorf("unsupported --fail-on value %q: expected upgradable or all", v)
	}
}
