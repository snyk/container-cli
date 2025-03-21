// © 2023-2025 Snyk Limited All rights reserved.
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
