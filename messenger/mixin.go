package messenger

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/MixinNetwork/bot-api-go-client"
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
	conf           *MixinConfiguration
	conversationId string
	recv           chan []byte
	send           chan *mixin.MessageRequest
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
		conf:           conf,
		conversationId: conf.ConversationId,
		recv:           make(chan []byte, conf.Buffer),
		send:           make(chan *mixin.MessageRequest, conf.Buffer),
	}
	go mm.loopReceive(ctx)
	go mm.loopSend(ctx, time.Second, conf.Buffer)

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

func (mm *MixinMessenger) BroadcastPlainMessage(ctx context.Context, data string) error {
	msg := &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId("", []byte(data)),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) BroadcastMessage(ctx context.Context, b []byte) error {
	msg := mm.buildMessage("", b)
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) SendMessage(ctx context.Context, receiver string, b []byte) error {
	msg := mm.buildMessage(receiver, b)
	return mm.client.SendMessage(ctx, msg)
}

func (mm *MixinMessenger) QueueMessage(ctx context.Context, receiver string, b []byte) error {
	msg := mm.buildMessage(receiver, b)
	select {
	case mm.send <- msg:
		return nil
	case <-ctx.Done():
		return ErrorDone
	}
}

func (mm *MixinMessenger) buildMessage(receiver string, b []byte) *mixin.MessageRequest {
	data := base64.RawURLEncoding.EncodeToString(b)
	return &mixin.MessageRequest{
		ConversationID: mm.conversationId,
		RecipientID:    receiver,
		Category:       mixin.MessageCategoryPlainText,
		MessageID:      uniqueMessageId(receiver, b),
		Data:           base64.RawURLEncoding.EncodeToString([]byte(data)),
	}
}

func (mm *MixinMessenger) loopReceive(ctx context.Context) {
	for {
		blaze := bot.NewBlazeClient(mm.conf.UserId, mm.conf.SessionId, mm.conf.Key)
		err := blaze.Loop(context.Background(), mm)
		logger.Errorf("blaze.Loop %s\n", err)
		if ctx.Err() != nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
}

func (mm *MixinMessenger) loopSend(ctx context.Context, period time.Duration, size int) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	var batch []*mixin.MessageRequest
	filter := make(map[string]bool)
	for {
		select {
		case msg := <-mm.send:
			if filter[msg.MessageID] {
				continue
			}
			filter[msg.MessageID] = true
			batch = append(batch, msg)
			if len(batch) > size {
				err := mm.sendMessagesWithoutTimeout(ctx, batch)
				if err != nil {
					logger.Errorf("sendMessagesWithoutTimeout %s\n", err)
				}
				filter = make(map[string]bool)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				err := mm.sendMessagesWithoutTimeout(ctx, batch)
				if err != nil {
					logger.Errorf("sendMessagesWithoutTimeout %s\n", err)
				}
				filter = make(map[string]bool)
				batch = nil
			}
		}
	}
}

func (mm *MixinMessenger) OnMessage(ctx context.Context, msg bot.MessageView, userId string) error {
	if msg.Category != mixin.MessageCategoryPlainText {
		return nil
	}
	if msg.ConversationId != mm.conversationId {
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
	sender, err := uuid.FromString(msg.UserId)
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

func (mm *MixinMessenger) OnAckReceipt(ctx context.Context, msg bot.MessageView, userId string) error {
	return nil
}

func (mm *MixinMessenger) SyncAck() bool {
	return true
}

func (mm *MixinMessenger) sendMessagesWithoutTimeout(ctx context.Context, batch []*mixin.MessageRequest) error {
	for {
		err := mm.client.SendMessages(ctx, batch)
		if err != nil && strings.Contains(err.Error(), "Client.Timeout exceeded") {
			continue
		}
		return err
	}
}

func uniqueMessageId(receiver string, b []byte) string {
	s := hex.EncodeToString(b)
	return mixin.UniqueConversationID(receiver, s)
}
