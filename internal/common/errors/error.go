package errors

type ContainerExtensionError struct {
	err     error
	userMsg string
}

func (xerr ContainerExtensionError) Error() string {
	return xerr.userMsg
}
