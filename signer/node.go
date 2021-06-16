package signer

import (
	"context"

	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
)

type Configuration struct {
	Key     string   `toml:"key"`
	Signers []string `toml:"signers"`
}

type Node struct {
	store     store.Storage
	messenger messenger.Messenger

	setupActions map[string]*Message

	key     kyber.Scalar
	signers []kyber.Point
}

func NewNode(ctx context.Context, store store.Storage, messenger messenger.Messenger, conf *Configuration) *Node {
	node := &Node{
		store:        store,
		messenger:    messenger,
		setupActions: make(map[string]*Message),
	}
	scaler, err := PrivateKeyFromHex(conf.Key)
	if err != nil {
		panic(conf.Key)
	}
	node.key = scaler
	for _, s := range conf.Signers {
		point, err := PubKeyFromBase58(s)
		if err != nil {
			panic(s)
		}
		node.signers = append(node.signers, point)
	}
	return node
}

func (node *Node) Run(ctx context.Context) error {
	for {
		b, err := node.messenger.ReceiveMessage(ctx)
		if err != nil {
			return err
		}
		msg, err := parseMessage(b)
		if err != nil {
			panic(err)
		}
		switch msg.Action {
		case MessageActionSetup:
			node.handleSetupMessage(msg)
		}
	}
}

func (node *Node) Threshold() int {
	return len(node.signers)*2/3 + 1
}
