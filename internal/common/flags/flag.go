package flags

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

type Flag interface {
	GetFlagSet() *pflag.FlagSet
	GetAsCLIArgument(configuration.Configuration) string
}
