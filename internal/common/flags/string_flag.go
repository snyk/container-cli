package flags

import (
	"fmt"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type StringFlag struct {
	*BaseFlag
}

func NewStringFlag(name string, defaultValue string, usage string) *StringFlag {
	f := StringFlag{
		BaseFlag: InitBaseFlag(name),
	}
	f.FlagSet.String(name, defaultValue, usage)
	return &f
}

func NewShortHandStringFlag(name string, shorthand string, defaultValue string, usage string) *StringFlag {
	f := StringFlag{
		BaseFlag: InitBaseFlag(name),
	}
	f.FlagSet.StringP(name, shorthand, defaultValue, usage)
	return &f
}

func (f *StringFlag) GetFlagValue(c configuration.Configuration) string {
	return c.GetString(f.Name)
}

func (f *StringFlag) GetAsCLIArgument(c configuration.Configuration) string {
	v := f.GetFlagValue(c)
	return fmt.Sprintf("--%s=%s", f.Name, v)
}
