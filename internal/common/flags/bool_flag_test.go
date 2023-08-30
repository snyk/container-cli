package flags_test

import (
	"testing"

	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
)

func Test_NewBoolFlag_GivenNameAndDefaultValueAndUsage_ShouldReturnBoolFlagWithFlagSetPopulatedWithBoolFlagAndShorthandShouldBeEmpty(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := true
	flagUsage := "test_flag_usage"

	result := flags.NewBoolFlag(flagName, flagDefaultValue, flagUsage)

	assertFlagSet(result, flagName, "", flagDefaultValue, flagUsage, t)
}

func Test_NewShortHandBoolFlag_GivenNameAndShorthandAndDefaultValueAndUsage_ShouldReturnBoolFlagWithFlagSetPopulatedWithBoolFlag(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := true
	flagUsage := "test_flag_usage"
	flagShorthand := "s"

	result := flags.NewShortHandBoolFlag(flagName, flagShorthand, flagDefaultValue, flagUsage)

	assertFlagSet(result, flagName, flagShorthand, flagDefaultValue, flagUsage, t)
}

func Test_GetAsCLIArgument_GivenBoolFlagAndConfig_ShouldReturnFlagAsCliArgument(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := true
	flagUsage := "test_flag_usage"
	c := configuration.New()

	unit := flags.NewBoolFlag(flagName, flagDefaultValue, flagUsage)
	c.AddFlagSet(unit.FlagSet)

	result := unit.GetAsCLIArgument(c)

	require.Equal(t, "--"+flagName, result)
}

func assertFlagSet(bf *flags.BoolFlag, expectedName string, expectedShorthand string, expectedDefaultValue bool, expectedUsage string, t *testing.T) {
	// TODO: this is asserting the library and i wouldn't like to do this.. instead i would like to mock it and verify the fs.Bool func has called
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
