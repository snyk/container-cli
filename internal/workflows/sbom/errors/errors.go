// © 2023-2026 Snyk Limited All rights reserved.
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

package errors

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	containererrors "github.com/snyk/container-cli/internal/common/errors"
)

type SbomErrorFactory struct {
	*containererrors.ErrorFactory
}

func NewSbomErrorFactory(logger *zerolog.Logger) *SbomErrorFactory {
	return &SbomErrorFactory{
		ErrorFactory: containererrors.NewErrorFactory(logger),
	}
}

func (ef *SbomErrorFactory) NewEmptySbomFormatError(
	validSbomFormats []string,
) *containererrors.ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("no format provided"),
		fmt.Sprintf(
			"Must set `--format` flag to specify an SBOM format. "+
				"Available formats are: %s",
			strings.Join(validSbomFormats, ", "),
		),
	)
}

func (ef *SbomErrorFactory) NewInvalidSbomFormatError(
	invalid string, validSbomFormats []string,
) *containererrors.ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("invalid format provided (%s)", invalid),
		fmt.Sprintf(
			"The format provided (%s) is not one of the available formats. "+
				"Available formats are: %s",
			invalid,
			strings.Join(validSbomFormats, ", "),
		),
	)
}

func (ef *SbomErrorFactory) NewInvalidPlatformError(
	invalid string, validPlatforms []string,
) *containererrors.ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("invalid platform provided (%s)", invalid),
		fmt.Sprintf(
			"The platform provided (%s) is not one of the available platforms. "+
				"Available platforms are: %s",
			invalid,
			strings.Join(validPlatforms, ", "),
		),
	)
}

func (ef *SbomErrorFactory) NewDepGraphWorkflowError(err error) *containererrors.ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("error while invoking depgraph workflow: %w", err),
		"An error occurred while running the underlying analysis needed to generate the SBOM.",
	)
}

func (ef *SbomErrorFactory) NewInternalError(err error) *containererrors.ContainerExtensionError {
	return ef.NewError(
		err,
		"An error occurred while running the underlying analysis which is required to generate the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func (ef *SbomErrorFactory) NewRemoteError(err error) *containererrors.ContainerExtensionError {
	return ef.NewError(
		err,
		"An error occurred while generating the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func (ef *SbomErrorFactory) NewBadRequestError(err error) *containererrors.ContainerExtensionError {
	return ef.NewError(
		err,
		"SBOM generation failed due to bad input arguments. "+
			"Please make sure you are using the latest version of the Snyk CLI.",
	)
}

func (ef *SbomErrorFactory) NewUnauthorizedError(err error) *containererrors.ContainerExtensionError {
	return ef.NewError(
		err,
		"Snyk failed to authenticate you based on your API token. "+
			"Please ensure that you have authenticated by running `snyk auth`.",
	)
}

func (ef *SbomErrorFactory) NewForbiddenError(err error, orgID string) *containererrors.ContainerExtensionError {
	return ef.NewError(
		err,
		fmt.Sprintf(
			"Your account is not authorized to perform this action. "+
				"Please ensure that you belong to the given organization and that "+
				"the organization is entitled to use the Snyk API. (Org ID: %s)",
			orgID,
		),
	)
}
