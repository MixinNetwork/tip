package messenger

import "fmt"

var (
	ErrorDone = newError("DONE")
)

func newError(msg string) error {
	return fmt.Errorf("messenger error: %s", msg)
}
