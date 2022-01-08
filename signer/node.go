package signer

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"golang.org/x/crypto/sha3"
)

type Configuration struct {
	Key     string   `toml:"key"`
	Signers []string `toml:"signers"`
}

type Node struct {
	store     store.Storage
	messenger messenger.Messenger

	setupActions map[string]*SetupBundle
	dkgStarted   bool
	dkgDone      context.CancelFunc
	board        *Board

	key      kyber.Scalar
	identity kyber.Point
	index    int
	signers  []dkg.Node
	phaser   chan dkg.Phase
	counter  int

	share *share.PriShare
	poly  []kyber.Point
}

func NewNode(ctx context.Context, cancel context.CancelFunc, store store.Storage, messenger messenger.Messenger, conf *Configuration) *Node {
	node := &Node{
		store:        store,
		messenger:    messenger,
		setupActions: make(map[string]*SetupBundle),
		dkgDone:      cancel,
		phaser:       make(chan dkg.Phase),
		index:        -1,
	}
	scalar, err := crypto.PrivateKeyFromHex(conf.Key)
	if err != nil {
		panic(conf.Key)
	}
	node.key = scalar
	node.identity = crypto.PublicKey(scalar)
	var group []byte
	sort.Slice(conf.Signers, func(i, j int) bool { return conf.Signers[i] < conf.Signers[j] })
	for i, s := range conf.Signers {
		point, err := crypto.PubKeyFromBase58(s)
		if err != nil {
			panic(s)
		}
		group = append(group, crypto.PublicKeyBytes(point)...)
		node.signers = append(node.signers, dkg.Node{
			Index:  uint32(i),
			Public: point,
		})
		if node.identity.Equal(point) {
			node.index = i
		}
	}
	groupId := sha3.Sum256(group)
	valid, err := store.CheckPolyGroup(groupId[:])
	if err != nil || !valid {
		panic(fmt.Errorf("Group check failed %v %v", valid, err))
	}
	if node.index < 0 {
		panic(node.index)
	}

	logger.Infof("Idenity: %s\n", crypto.PublicKeyString(node.identity))

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

func (node *Node) GetKey() kyber.Scalar {
	return node.key
}

func (node *Node) GetSigners() []dkg.Node {
	return node.signers
}

func (node *Node) GetShare() *share.PriShare {
	return node.share
}

func (node *Node) GetPoly() []kyber.Point {
	return node.poly
}

func (node *Node) Run(ctx context.Context) error {
	if node.share != nil || node.poly != nil {
		return nil
	}
	for {
		_, b, err := node.messenger.ReceiveMessage(ctx)
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
			nonce, db, err := decodeDealBundle(msg.Data)
			logger.Verbose("DEAL", nonce, err)
			if err != nil {
				continue
			}
			if !node.dkgStarted {
				node.setup(ctx, nonce)
			}
			node.board.deals <- *db
			node.counter += 1
			logger.Verbose("DEAL COUNTER", node.counter)
			if node.counter+1 == len(node.signers) {
				node.phaser <- dkg.ResponsePhase
				node.counter = 0
			}
		case MessageActionDKGResponse:
			rb, err := decodeResponseBundle(msg.Data)
			logger.Verbose("RESPONSE", err)
			if err != nil || node.board == nil {
				continue
			}
			node.board.resps <- *rb
			node.counter += 1
			logger.Verbose("RESPONSE COUNTER", node.counter)
			if node.counter+1 == len(node.signers) {
				node.phaser <- dkg.JustifPhase
				node.counter = 0
			}
		case MessageActionDKGJustify:
			jb, err := decodeJustificationBundle(msg.Data)
			logger.Verbose("JUSTIFICATION", err)
			if err != nil || node.board == nil {
				continue
			}
			node.board.justs <- *jb
			node.counter += 1
			logger.Verbose("JUSTIFICATION COUNTER", node.counter)
			if node.counter+1 == len(node.signers) {
				node.phaser <- dkg.FinishPhase
				node.counter = 0
			}
		}
	}
}

func (node *Node) Threshold() int {
	return len(node.signers)*2/3 + 1
}
