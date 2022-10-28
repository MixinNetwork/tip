package api

import "fmt"

var (
	ErrUnknown         = fmt.Errorf("server error")
	ErrInvalidAssignor = fmt.Errorf("invalid assignor")
	ErrTooManyRequest  = fmt.Errorf("too many request")
)
