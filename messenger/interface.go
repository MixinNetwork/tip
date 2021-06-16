package messenger

import "context"

type Messenger interface {
	ReceiveMessage(context.Context) ([]byte, error)
	SendMessage(ctx context.Context, b []byte) error
}
