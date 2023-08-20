package flags

import (
	"github.com/spf13/pflag"
)

type BaseFlag struct {
	Name    string
	FlagSet *pflag.FlagSet
}

func InitBaseFlag(name string) *BaseFlag {
	return &BaseFlag{
		Name:    name,
		FlagSet: pflag.NewFlagSet(name, pflag.ExitOnError),
	}
}

func (b BaseFlag) GetFlagSet() *pflag.FlagSet {
	return b.FlagSet
}
