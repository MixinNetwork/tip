package signer

import (
	"context"
	"encoding/hex"
	"sort"
	"time"

	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
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
	signers  []dkg.Node
	period   time.Duration

	share *share.PriShare
	poly  []kyber.Point
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
		node.signers = append(node.signers, dkg.Node{
			Index:  uint32(i),
			Public: point,
		})
		if node.identity.Equal(point) {
			node.index = i
		}
	}
	node.period = time.Second * time.Duration(conf.TimeoutSeconds)
	if node.index < 0 {
		panic(node.index)
	}

	logger.Infof("Idenity: %s\n", PublicKeyString(node.identity))

	poly, err := store.ReadPolyPublic()
	if err != nil {
		panic(err)
	} else if len(poly) > 0 {
		logger.Infof("Poly public: %s\n", hex.EncodeToString(poly))
		node.poly = unmarshalCommitments(poly)
	}

	priv, err := store.ReadPolyShare()
	if err != nil {
		panic(err)
	} else if len(priv) > 0 {
		logger.Infof("Poly share: %s\n", hex.EncodeToString(priv))
		node.share = unmarshalPrivShare(priv)
	}
	return node
}

func (node *Node) GetIdentity() kyber.Point {
	return node.identity
}

func (node *Node) GetSigners() []dkg.Node {
	return node.signers
}

func (node *Node) GetShare() share.PriShare {
	return *node.share
}

func (node *Node) GetPoly() []kyber.Point {
	return node.poly
}

func (node *Node) Run(ctx context.Context) error {
	for {
		b, err := node.messenger.ReceiveMessage(ctx)
		if err != nil {
			return err
		}
		msg, err := decodeMessage(b)
		if err != nil {
			logger.Errorf("msg decode error %d %s", len(b), err)
			continue
		}
		err = node.verifyMessage(msg)
		if err != nil {
			logger.Errorf("msg verify error %d %s", len(b), err)
			continue
		}
		switch msg.Action {
		case MessageActionSetup:
			err = node.handleSetupMessage(ctx, msg)
			logger.Verbose("SETUP", err)
		case MessageActionDKGDeal:
			db, err := decodeDealBundle(msg.Data)
			logger.Verbose("DEAL", err)
			if err == nil && node.board != nil {
				node.board.deals <- *db
			}
		case MessageActionDKGResponse:
			rb, err := decodeResponseBundle(msg.Data)
			logger.Verbose("RESPONSE", err)
			if err == nil && node.board != nil {
				node.board.resps <- *rb
			}
		case MessageActionDKGJustify:
			jb, err := decodeJustificationBundle(msg.Data)
			logger.Verbose("JUSTIFICATION", err)
			if err == nil && node.board != nil {
				node.board.justs <- *jb
			}
		}
	}
}

func (node *Node) Threshold() int {
	return len(node.signers)*2/3 + 1
}
