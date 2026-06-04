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
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// createLocalPolicy builds a LocalPolicy from the container test flags.
// Returns nil when no policy flags are provided, which preserves the legacy behaviour:
// the shim default SeverityLow only fires when TestConfiguration.LocalPolicy is entirely nil,
// and test-outcome-enricher-df writes outcome=FAIL for any finding — matching the legacy
// "exit 1 if any vuln exists" behaviour.
func createLocalPolicy(ictx workflow.InvocationContext) (*testapi.LocalPolicy, error) {
	cfg := ictx.GetConfiguration()

	severityThreshold := getSeverityThreshold(cfg)
	failOnUpgradable, err := getFailOnUpgradable(cfg)
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

func getSeverityThreshold(cfg configuration.Configuration) *testapi.Severity {
	v := cfg.GetString("severity-threshold")
	if v == "" {
		return nil
	}
	s := testapi.Severity(v)
	return &s
}

func getFailOnUpgradable(cfg configuration.Configuration) (*bool, error) {
	v := cfg.GetString("fail-on")
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

// buildTestConfig assembles the TestConfiguration for a container test invocation.
// publishReport should be nil for snyk container test and &true for snyk container monitor.
func buildTestConfig(ictx workflow.InvocationContext, localPolicy *testapi.LocalPolicy, publishReport *bool) *testapi.TestConfiguration {
	cfg := ictx.GetConfiguration()

	testConfig := &testapi.TestConfiguration{
		LocalPolicy: localPolicy,
		ScanConfig: &testapi.ScanConfiguration{
			Container: &testapi.ContainerScanConfiguration{},
		},
		PublishReport: publishReport,
	}

	if tr := cfg.GetString("target-reference"); tr != "" {
		testConfig.TargetReference = &tr
	}
	if pbc := cfg.GetString("project-business-criticality"); pbc != "" {
		testConfig.ProjectBusinessCriticality = &pbc
	}
	if pe := cfg.GetString("project-environment"); pe != "" {
		vals := strings.Split(pe, ",")
		testConfig.ProjectEnvironment = &vals
	}
	if pl := cfg.GetString("project-lifecycle"); pl != "" {
		vals := strings.Split(pl, ",")
		testConfig.ProjectLifecycle = &vals
	}
	if pt := cfg.GetString("project-tags"); pt != "" {
		vals := strings.Split(pt, ",")
		testConfig.ProjectTags = &vals
	}

	return testConfig
}
