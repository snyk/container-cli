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
