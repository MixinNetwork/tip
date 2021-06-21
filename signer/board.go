package signer

import (
	"context"

	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
)

type Board struct {
	messenger messenger.Messenger
	nonce     uint64
	deals     chan dkg.DealBundle
	resps     chan dkg.ResponseBundle
	justs     chan dkg.JustificationBundle
	ctx       context.Context
	key       kyber.Scalar
}

func (node *Node) NewBoard(ctx context.Context, nonce uint64) *Board {
	n := len(node.signers)
	return &Board{
		messenger: node.messenger,
		nonce:     nonce,
		deals:     make(chan dkg.DealBundle, n),
		resps:     make(chan dkg.ResponseBundle, n),
		justs:     make(chan dkg.JustificationBundle, n),
		ctx:       ctx,
		key:       node.key,
	}
}

func (t *Board) PushDeals(db *dkg.DealBundle) {
	data := encodeDealBundle(db, t.nonce)
	msg := makeMessage(t.key, MessageActionDKGDeal, data)
	err := t.messenger.SendMessage(t.ctx, msg)
	logger.Verbose("PushDeals", len(msg), err)
}

func (t *Board) IncomingDeal() <-chan dkg.DealBundle {
	return t.deals
}

func (t *Board) PushResponses(rb *dkg.ResponseBundle) {
	data := encodeResponseBundle(rb)
	msg := makeMessage(t.key, MessageActionDKGResponse, data)
	err := t.messenger.SendMessage(t.ctx, msg)
	logger.Verbose("PushResponses", len(msg), err)
}

func (t *Board) IncomingResponse() <-chan dkg.ResponseBundle {
	return t.resps
}

func (t *Board) PushJustifications(jb *dkg.JustificationBundle) {
	data := encodeJustificationBundle(jb)
	msg := makeMessage(t.key, MessageActionDKGJustify, data)
	err := t.messenger.SendMessage(t.ctx, msg)
	logger.Verbose("PushJustifications", len(msg), err)
}

func (t *Board) IncomingJustification() <-chan dkg.JustificationBundle {
	return t.justs
}
