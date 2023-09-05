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
