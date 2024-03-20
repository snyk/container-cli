// © 2023-2024 Snyk Limited All rights reserved.
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
