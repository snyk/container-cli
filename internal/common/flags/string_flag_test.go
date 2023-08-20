package flags_test

import (
	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_NewStringFlag_GivenNameAndDefaultValueAndUsage_ShouldReturnStringFlagWithFlagSetPopulatedWithStringFlagAndShorthandShouldBeEmpty(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := "test_flag_value"
	flagUsage := "test_flag_usage"

	result := flags.NewStringFlag(flagName, flagDefaultValue, flagUsage)

	assertStringFlag(result, flagName, "", flagDefaultValue, flagUsage, t)
}

func Test_NewShortHandBoolFlag_GivenNameAndShorthandAndDefaultValueAndUsage_ShouldReturnStringFlagWithFlagSetPopulatedWithStringFlag(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := "test_flag_value"
	flagUsage := "test_flag_usage"
	flagShorthand := "s"

	result := flags.NewShortHandStringFlag(flagName, flagShorthand, flagDefaultValue, flagUsage)

	assertStringFlag(result, flagName, flagShorthand, flagDefaultValue, flagUsage, t)
}

func Test_GetAsCLIArgument_GivenStringFlagAndConfig_ShouldReturnFlagAsCliArgument(t *testing.T) {
	flagName := "test_flag_name"
	flagDefaultValue := "test_flag_value"
	flagUsage := "test_flag_usage"
	c := configuration.New()

	unit := flags.NewStringFlag(flagName, flagDefaultValue, flagUsage)
	c.AddFlagSet(unit.FlagSet)

	result := unit.GetAsCLIArgument(c)

	require.Equal(t, "--"+flagName+"="+flagDefaultValue, result)
}

func assertStringFlag(bf *flags.StringFlag, expectedName string, expectedShorthand string, expectedDefaultValue string, expectedUsage string, t *testing.T) {
	// TODO: this is asserting the library and i wouldn't like to do this.. instead i would like to mock it and verify the fs.Bool func has called
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
