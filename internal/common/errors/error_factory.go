package errors

import (
	"github.com/rs/zerolog"
)

type ErrorFactory struct {
	logger *zerolog.Logger
}

func NewErrorFactory(logger *zerolog.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

func (ef *ErrorFactory) NewError(err error, userMsg string) *ContainerExtensionError {
	ef.logger.Error().Err(err).Send()

	return &ContainerExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}
