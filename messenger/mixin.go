package messenger

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/MixinNetwork/tip/logger"
	"github.com/fox-one/mixin-sdk-go"
	"github.com/gofrs/uuid"
)

type MixinConfiguration struct {
	UserId         string `toml:"user"`
	SessionId      string `toml:"session"`
	Key            string `toml:"key"`
	Buffer         int    `toml:"buffer"`
	ConversationId string `toml:"conversation"`
}

type MixinMessenger struct {
	client         *mixin.Client
	conversationId string
	recv           chan []byte
}

func NewMixinMessenger(ctx context.Context, conf *MixinConfiguration) (*MixinMessenger, error) {
	s := &mixin.Keystore{
		ClientID:   conf.UserId,
		SessionID:  conf.SessionId,
		PrivateKey: conf.Key,
	}

	client, err := mixin.NewFromKeystore(s)
	if err != nil {
		return nil, err
	}

	mm := &MixinMessenger{
		client:         client,
		conversationId: conf.ConversationId,
		recv:           make(chan []byte, conf.Buffer),
	}
	go mm.loop(ctx)

	return mm, nil
}

func (mm *MixinMessenger) ReceiveMessage(ctx context.Context) (string, []byte, error) {
	select {
	case b := <-mm.recv:
		sender, err := uuid.FromBytes(b[:16])
		if err != nil {
			panic(err)
		}
		return sender.String(), b[16:], nil
	case <-ctx.Done():
		return "", nil, ErrorDone
	}
}

func (mm *MixinMessenger) BroadcastMessage(ctx context.Context, b []byte) error {
	data := base64.RawURLEncoding.EncodeToString(b)
	msg := &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId(b),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) SendMessage(ctx context.Context, receiver string, b []byte) error {
	data := base64.RawURLEncoding.EncodeToString(b)
	msg := &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		RecipientID:    receiver,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId(b),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) loop(ctx context.Context) {
	for {
		err := mm.client.LoopBlaze(context.Background(), mm)
		logger.Errorf("LoopBlaze %s\n", err)
		if ctx.Err() != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
}

func (mm *MixinMessenger) OnMessage(ctx context.Context, msg *mixin.MessageView, userId string) error {
	if msg.Category != mixin.MessageCategoryPlainText {
		return nil
	}
	if msg.ConversationID != mm.conversationId {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(msg.Data)
	if err != nil {
		return nil
	}
	data, err = base64.RawURLEncoding.DecodeString(string(data))
	if err != nil {
		return nil
	}
	sender, err := uuid.FromString(msg.UserID)
	if err != nil {
		return nil
	}
	data = append(sender.Bytes(), data...)
	select {
	case mm.recv <- data:
	case <-ctx.Done():
	}
	return nil
}

func (mm *MixinMessenger) OnAckReceipt(ctx context.Context, msg *mixin.MessageView, userId string) error {
	return nil
}

func uniqueMessageId(b []byte) string {
	s := hex.EncodeToString(b)
	return mixin.UniqueConversationID(s, s)
}
