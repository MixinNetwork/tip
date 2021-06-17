package signer

import (
	"context"

	"github.com/MixinNetwork/tip/messenger"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
)

type Board struct {
	messenger messenger.Messenger
	deals     chan dkg.DealBundle
	resps     chan dkg.ResponseBundle
	justs     chan dkg.JustificationBundle
	ctx       context.Context
	key       kyber.Scalar
}

func (node *Node) NewBoard(ctx context.Context) *Board {
	n := len(node.signers)
	return &Board{
		messenger: node.messenger,
		deals:     make(chan dkg.DealBundle, n),
		resps:     make(chan dkg.ResponseBundle, n),
		justs:     make(chan dkg.JustificationBundle, n),
		ctx:       ctx,
		key:       node.key,
	}
}

func (t *Board) PushDeals(db *dkg.DealBundle) {
	data := encodeDealBundle(db)
	msg := t.makeMessage(MessageActionDKGDeal, data)
	t.messenger.SendMessage(t.ctx, msg)
}

func (t *Board) IncomingDeal() <-chan dkg.DealBundle {
	return t.deals
}

func (t *Board) PushResponses(rb *dkg.ResponseBundle) {
	data := encodeResponseBundle(rb)
	msg := t.makeMessage(MessageActionDKGResponse, data)
	t.messenger.SendMessage(t.ctx, msg)
}

func (t *Board) IncomingResponse() <-chan dkg.ResponseBundle {
	return t.resps
}

func (t *Board) PushJustifications(jb *dkg.JustificationBundle) {
	data := encodeJustificationBundle(jb)
	msg := t.makeMessage(MessageActionDKGJustify, data)
	t.messenger.SendMessage(t.ctx, msg)
}

func (t *Board) IncomingJustification() <-chan dkg.JustificationBundle {
	return t.justs
}
