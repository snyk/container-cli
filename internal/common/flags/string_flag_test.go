package flags_test

import (
	"fmt"
	"testing"

	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

const testStringFlagName = "test_string_flag_name"
const testStringFlagDefaultValue = "test_string_flag_value"
const testStringFlagUsage = "test_string_flag_usage"

func Test_NewStringFlag_GivenNameAndDefaultValueAndUsage_ShouldReturnStringFlagWithFlagSetPopulatedWithStringFlagAndShorthandShouldBeEmpty(t *testing.T) {
	result := flags.NewStringFlag(testStringFlagName, testStringFlagDefaultValue, testStringFlagUsage)

	assertStringFlag(result, testStringFlagName, "", testStringFlagDefaultValue, testStringFlagUsage, t)
}

func Test_NewShortHandBoolFlag_GivenNameAndShorthandAndDefaultValueAndUsage_ShouldReturnStringFlagWithFlagSetPopulatedWithStringFlag(t *testing.T) {
	flagShorthand := "s"

	result := flags.NewShortHandStringFlag(
		testStringFlagName,
		flagShorthand,
		testStringFlagDefaultValue,
		testStringFlagUsage,
	)

	assertStringFlag(result, testStringFlagName, flagShorthand, testStringFlagDefaultValue, testStringFlagUsage, t)
}

func Test_GetAsCLIArgument_GivenStringFlagAndConfig_ShouldReturnFlagAsCliArgument(t *testing.T) {
	c := configuration.New()

	unit := flags.NewStringFlag(testStringFlagName, testStringFlagDefaultValue, testStringFlagUsage)
	err := c.AddFlagSet(unit.FlagSet)
	require.NoError(t, err)

	result := unit.GetAsCLIArgument(c)

	require.Equal(t, fmt.Sprintf("--%s=%s", testStringFlagName, testStringFlagDefaultValue), result)
}

func assertStringFlag(
	bf *flags.StringFlag,
	expectedName string,
	expectedShorthand string,
	expectedDefaultValue string,
	expectedUsage string,
	t *testing.T,
) {
	require.True(t, bf.FlagSet.HasFlags())

	flag := bf.FlagSet.Lookup(expectedName)
	require.Equal(t, expectedName, flag.Name)
	require.Equal(t, expectedShorthand, flag.Shorthand)
	require.Equal(t, expectedUsage, flag.Usage)

	defaultValue, ok := bf.FlagSet.GetString(expectedName)
	if ok != nil {
		t.Error(ok)
	}
	require.Equal(t, expectedDefaultValue, defaultValue)
}
