package signer

import (
	"context"
	"sort"
	"time"

	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
)

type Configuration struct {
	Key            string   `toml:"key"`
	Signers        []string `toml:"signers"`
	TimeoutSeconds int      `toml:"timeout"`
}

type Node struct {
	store     store.Storage
	messenger messenger.Messenger

	setupActions map[string]*SetupBundle
	board        *Board

	key      kyber.Scalar
	identity kyber.Point
	index    int
	signers  []kyber.Point
	period   time.Duration
}

func NewNode(ctx context.Context, store store.Storage, messenger messenger.Messenger, conf *Configuration) *Node {
	node := &Node{
		store:        store,
		messenger:    messenger,
		setupActions: make(map[string]*SetupBundle),
		index:        -1,
	}
	scalar, err := PrivateKeyFromHex(conf.Key)
	if err != nil {
		panic(conf.Key)
	}
	node.key = scalar
	node.identity = PublicKey(scalar)
	sort.Slice(conf.Signers, func(i, j int) bool { return conf.Signers[i] < conf.Signers[j] })
	for i, s := range conf.Signers {
		point, err := PubKeyFromBase58(s)
		if err != nil {
			panic(s)
		}
		node.signers = append(node.signers, point)
		if node.identity.Equal(point) {
			node.index = i
		}
	}
	node.period = time.Second * time.Duration(conf.TimeoutSeconds)
	if node.index < 0 {
		panic(node.index)
	}
	return node
}

func (node *Node) Run(ctx context.Context) error {
	for {
		b, err := node.messenger.ReceiveMessage(ctx)
		if err != nil {
			return err
		}
		msg, err := decodeMessage(b)
		if err != nil {
			panic(err)
		}
		switch msg.Action {
		case MessageActionSetup:
			node.handleSetupMessage(ctx, msg)
		case MessageActionDKGDeal:
			db, err := decodeDealBundle(msg.Data)
			if err != nil {
				node.board.deals <- *db
			}
		case MessageActionDKGResponse:
			rb, err := decodeResponseBundle(msg.Data)
			if err != nil {
				node.board.resps <- *rb
			}
		case MessageActionDKGJustify:
			jb, err := decodeJustificationBundle(msg.Data)
			if err != nil {
				node.board.justs <- *jb
			}
		}
	}
}

func (node *Node) Threshold() int {
	return len(node.signers)*2/3 + 1
}
