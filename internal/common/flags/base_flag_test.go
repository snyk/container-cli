package flags_test

import (
	"testing"

	"github.com/snyk/container-cli/internal/common/flags"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func Test_InitBaseFlag_GivenName_ShouldInitBaseFlagNameAndInitNewEmptyFlagSet(t *testing.T) {
	flagName := "test_flag_name"

	result := flags.InitBaseFlag(flagName)

	require.Equal(t, flagName, result.Name)
	require.IsType(t, &pflag.FlagSet{}, result.FlagSet)
	require.False(t, result.FlagSet.HasFlags())
}
