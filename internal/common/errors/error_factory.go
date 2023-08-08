package errors

import "log"

type ErrorFactory struct {
	logger *log.Logger
}

func NewErrorFactory(logger *log.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

func (ef *ErrorFactory) NewError(err error, userMsg string) *ContainerExtensionError {
	ef.logger.Printf("ERROR: %s\n", err)

	return &ContainerExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}
