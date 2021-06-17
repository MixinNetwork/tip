package signer

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"golang.org/x/crypto/sha3"
)

func (node *Node) Setup(ctx context.Context, nonce uint64) error {
	priv, err := node.store.ReadPolyShare()
	if err != nil || priv != nil {
		return err
	}
	pub, err := node.store.ReadPolyPublic()
	if err != nil || pub != nil {
		return err
	}

	pub, priv, err = node.runDKG(ctx, nonce)
	if err != nil {
		return err
	}
	return node.store.WritePoly(pub, priv)
}

func (node *Node) runDKG(ctx context.Context, nonce uint64) ([]byte, []byte, error) {
	suite := bn256.NewSuiteG2()
	conf := &dkg.Config{
		Suite:     suite,
		Threshold: node.Threshold(),
		Longterm:  node.key,
		Nonce:     node.getNonce(nonce),
		Auth:      bls.NewSchemeOnG1(suite),
		FastSync:  false,
		NewNodes:  nil,
	}

	node.board = node.NewBoard(ctx)
	phaser := dkg.NewTimePhaserFunc(func(dkg.Phase) {
		time.Sleep(node.period)
	})
	protocol, err := dkg.NewProtocol(conf, node.board, phaser, false)
	if err != nil {
		return nil, nil, err
	}
	resCh := protocol.WaitEnd()
	phaser.Start()
	optRes := <-resCh
	if optRes.Error != nil {
		return nil, nil, optRes.Error
	}
	res := optRes.Result
	if i := res.Key.PriShare().I; i != node.index {
		return nil, nil, fmt.Errorf("private share index malformed %d %d", node.index, i)
	}
	priv := marshalPrivShare(res.Key.PriShare())
	pub := marshalCommitments(res.Key.Commitments())
	return priv, pub, nil
}

func marshalPrivShare(ps *share.PriShare) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(ps.I))
	b, err := ps.V.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return append(buf[:], b...)
}

func marshalCommitments(commits []kyber.Point) []byte {
	var data []byte
	for _, p := range commits {
		b, err := p.MarshalBinary()
		if err != nil {
			panic(err)
		}
		data = append(data, b...)
	}
	return data
}

func (node *Node) getNonce(nonce uint64) []byte {
	var data []byte
	for _, s := range node.signers {
		b, err := s.MarshalBinary()
		if err != nil {
			panic(s)
		}
		data = append(data, b...)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], nonce)
	data = append(data, buf[:]...)
	sum := sha3.Sum256(data)
	return sum[:]
}
