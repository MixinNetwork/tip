package signer

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/logger"
	"github.com/drand/kyber"
	"github.com/drand/kyber/group/mod"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"golang.org/x/crypto/sha3"
)

func (node *Node) setup(ctx context.Context, nonce uint64) error {
	if node.dkgStarted {
		return nil
	}
	node.dkgStarted = true

	priv, err := node.store.ReadPolyShare()
	if err != nil || priv != nil {
		return err
	}
	pub, err := node.store.ReadPolyPublic()
	if err != nil || pub != nil {
		return err
	}

	suite := bn256.NewSuiteG2()
	conf := &dkg.Config{
		Suite:     suite,
		Threshold: node.Threshold(),
		Longterm:  node.key,
		Nonce:     node.getNonce(nonce),
		Auth:      bls.NewSchemeOnG1(suite),
		FastSync:  false,
		NewNodes:  node.signers,
	}

	node.board = node.NewBoard(ctx, nonce)
	phaser := dkg.NewTimePhaserFunc(func(dkg.Phase) {
		time.Sleep(node.period)
	})
	protocol, err := dkg.NewProtocol(conf, node.board, phaser, false)
	if err != nil {
		return err
	}
	go phaser.Start()
	go func() error {
		pub, priv, err = node.runDKG(ctx, protocol)
		logger.Verbose("runDKG", hex.EncodeToString(pub), hex.EncodeToString(priv), err)
		if err != nil {
			return err
		}
		return node.store.WritePoly(pub, priv)
	}()
	return nil
}

func (node *Node) runDKG(ctx context.Context, protocol *dkg.Protocol) ([]byte, []byte, error) {
	resCh := protocol.WaitEnd()
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
	return pub, priv, nil
}

func unmarshalPrivShare(b []byte) share.PriShare {
	var ps share.PriShare
	ps.V = mod.NewInt64(0, bn256.Order).SetBytes(b[4:])
	ps.I = int(binary.BigEndian.Uint32(b[:4]))
	return ps
}

func marshalPrivShare(ps *share.PriShare) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(ps.I))
	b := crypto.PrivateKeyBytes(ps.V)
	return append(buf[:], b...)
}

func unmarshalCommitments(b []byte) []kyber.Point {
	var commits []kyber.Point
	for i, l := 0, len(b)/128; i < l; i++ {
		point, err := crypto.PubKeyFromBytes(b[i*128 : (i+1)*128])
		if err != nil {
			panic(err)
		}
		commits = append(commits, point)
	}
	return commits
}

func marshalCommitments(commits []kyber.Point) []byte {
	var data []byte
	for _, p := range commits {
		b := crypto.PublicKeyBytes(p)
		data = append(data, b...)
	}
	return data
}

func (node *Node) getNonce(nonce uint64) []byte {
	var data []byte
	for _, s := range node.signers {
		b := crypto.PublicKeyBytes(s.Public)
		data = append(data, b...)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], nonce)
	data = append(data, buf[:]...)
	sum := sha3.Sum256(data)
	return sum[:]
}
