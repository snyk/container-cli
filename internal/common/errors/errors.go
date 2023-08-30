package errors

import "fmt"

func (ef *ErrorFactory) NewEmptyOrgError() *ContainerExtensionError {
	return ef.NewError(
		fmt.Errorf("failed to determine org id"),
		"Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	)
}
