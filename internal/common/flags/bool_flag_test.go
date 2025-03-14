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

package flags_test

import (
	"fmt"
	"testing"

	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

const testBoolFlagName = "test_bool_flag_name"
const testBoolFlagDefaultValue = true
const testBoolFlagUsage = "test_bool_flag_usage"

func Test_NewBoolFlag_GivenNameAndDefaultValueAndUsage_ShouldReturnBoolFlagWithFlagSetPopulatedWithBoolFlagAndShorthandShouldBeEmpty(t *testing.T) {
	result := flags.NewBoolFlag(testBoolFlagName, testBoolFlagDefaultValue, testBoolFlagUsage)

	assertFlagSet(result, testBoolFlagName, "", testBoolFlagDefaultValue, testBoolFlagUsage, t)
}

func Test_NewShortHandBoolFlag_GivenNameAndShorthandAndDefaultValueAndUsage_ShouldReturnBoolFlagWithFlagSetPopulatedWithBoolFlag(t *testing.T) {
	flagShorthand := "s"

	result := flags.NewShortHandBoolFlag(testBoolFlagName, flagShorthand, testBoolFlagDefaultValue, testBoolFlagUsage)

	assertFlagSet(result, testBoolFlagName, flagShorthand, testBoolFlagDefaultValue, testBoolFlagUsage, t)
}

func Test_GetAsCLIArgument_GivenBoolFlagAndConfig_ShouldReturnFlagAsCliArgument(t *testing.T) {
	c := configuration.New()

	unit := flags.NewBoolFlag(testBoolFlagName, testBoolFlagDefaultValue, testBoolFlagUsage)
	err := c.AddFlagSet(unit.FlagSet)
	require.NoError(t, err)

	result := unit.GetAsCLIArgument(c)

	require.Equal(t, fmt.Sprintf("--%s", testBoolFlagName), result)
}

func assertFlagSet(
	bf *flags.BoolFlag,
	expectedName string,
	expectedShorthand string,
	expectedDefaultValue bool,
	expectedUsage string,
	t *testing.T,
) {
	require.True(t, bf.FlagSet.HasFlags())

	flag := bf.FlagSet.Lookup(expectedName)
	require.Equal(t, expectedName, flag.Name)
	require.Equal(t, expectedShorthand, flag.Shorthand)
	require.Equal(t, expectedUsage, flag.Usage)

	defaultValue, ok := bf.FlagSet.GetBool(expectedName)
	if ok != nil {
		t.Fail()
	}
	require.Equal(t, expectedDefaultValue, defaultValue)
}
