package flags

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type BoolFlag struct {
	*BaseFlag
}

func NewBoolFlag(name string, defaultValue bool, usage string) *BoolFlag {
	f := BoolFlag{
		BaseFlag: InitBaseFlag(name),
	}
	f.FlagSet.Bool(name, defaultValue, usage)
	return &f
}

func NewShortHandBoolFlag(name string, shorthand string, defaultValue bool, usage string) *BoolFlag {
	f := BoolFlag{
		BaseFlag: InitBaseFlag(name),
	}
	f.FlagSet.BoolP(name, shorthand, defaultValue, usage)
	return &f
}

func (f *BoolFlag) GetFlagValue(c configuration.Configuration) bool {
	return c.GetBool(f.Name)
}

func (f *BoolFlag) GetAsCLIArgument(c configuration.Configuration) string {
	if v := f.GetFlagValue(c); v {
		return fmt.Sprintf("--%s", f.Name)
	}

	return ""
}
