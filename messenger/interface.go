package messenger

import "context"

type Messenger interface {
	ReceiveMessage(context.Context) (string, []byte, error)
	SendMessage(ctx context.Context, receiver string, b []byte) error
	QueueMessage(ctx context.Context, receiver string, b []byte) error
	BroadcastMessage(ctx context.Context, b []byte) error
	BroadcastPlainMessage(ctx context.Context, text string) error
}
