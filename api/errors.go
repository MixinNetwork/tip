package api

import "fmt"

var (
	ErrUnknown        = fmt.Errorf("server error")
	ErrTooManyRequest = fmt.Errorf("too many request")
)
