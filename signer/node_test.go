package signer

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"
)

type signerStoreStub struct {
	checkPolyGroupFn func([]byte) (bool, error)
	readPolyPublicFn func() ([]byte, error)
	readPolyShareFn  func() ([]byte, error)
	writePolyFn      func([]byte, []byte) error
}

func newSignerStoreStub() *signerStoreStub {
	return &signerStoreStub{
		checkPolyGroupFn: func([]byte) (bool, error) { return true, nil },
		readPolyPublicFn: func() ([]byte, error) { return nil, nil },
		readPolyShareFn:  func() ([]byte, error) { return nil, nil },
		writePolyFn:      func([]byte, []byte) error { return nil },
	}
}

func (s *signerStoreStub) CheckPolyGroup(group []byte) (bool, error) {
	return s.checkPolyGroupFn(group)
}
func (s *signerStoreStub) ReadPolyPublic() ([]byte, error)      { return s.readPolyPublicFn() }
func (s *signerStoreStub) ReadPolyShare() ([]byte, error)       { return s.readPolyShareFn() }
func (s *signerStoreStub) WritePoly(public, share []byte) error { return s.writePolyFn(public, share) }
func (*signerStoreStub) WriteAssignee([]byte, []byte) error     { return nil }
func (*signerStoreStub) ReadAssignor([]byte) ([]byte, error)    { return nil, nil }
func (*signerStoreStub) ReadAssignee([]byte) ([]byte, error)    { return nil, nil }
func (*signerStoreStub) CheckLimit([]byte, time.Duration, uint32, bool) (int, error) {
	return 0, nil
}
func (*signerStoreStub) CheckEphemeralNonce([]byte, []byte, uint64, time.Duration) (bool, error) {
	return false, nil
}
func (*signerStoreStub) RotateEphemeralNonce([]byte, []byte, uint64) error { return nil }
func (*signerStoreStub) WriteSignRequest([]byte, []byte) (time.Time, int, error) {
	return time.Time{}, 0, nil
}
func (*signerStoreStub) Watch([]byte) ([]byte, time.Time, int, error) {
	return nil, time.Time{}, 0, nil
}

type receivedMessage struct {
	body []byte
	err  error
}

type signerMessengerStub struct {
	received         []receivedMessage
	broadcasted      [][]byte
	plainBroadcasted []string
}

func (m *signerMessengerStub) ReceiveMessage(ctx context.Context) (string, []byte, error) {
	if len(m.received) == 0 {
		<-ctx.Done()
		return "", nil, messenger.ErrorDone
	}
	msg := m.received[0]
	m.received = m.received[1:]
	return "", msg.body, msg.err
}

func (*signerMessengerStub) SendMessage(context.Context, string, []byte) error  { return nil }
func (*signerMessengerStub) QueueMessage(context.Context, string, []byte) error { return nil }

func (m *signerMessengerStub) BroadcastMessage(_ context.Context, b []byte) error {
	m.broadcasted = append(m.broadcasted, append([]byte(nil), b...))
	return nil
}

func (m *signerMessengerStub) BroadcastPlainMessage(_ context.Context, text string) error {
	m.plainBroadcasted = append(m.plainBroadcasted, text)
	return nil
}

func TestNewNodeGettersAndThreshold(t *testing.T) {
	require := require.New(t)

	self := signerTestScalar()
	otherA := signerTestScalar()
	otherB := signerTestScalar()
	share := &share.PriShare{I: 1, V: signerTestScalar()}
	poly := []kyber.Point{
		crypto.PublicKey(signerTestScalar()),
		crypto.PublicKey(signerTestScalar()),
	}

	var checkedGroup []byte
	store := newSignerStoreStub()
	store.checkPolyGroupFn = func(group []byte) (bool, error) {
		checkedGroup = append([]byte(nil), group...)
		return true, nil
	}
	store.readPolyPublicFn = func() ([]byte, error) { return marshalCommitments(poly), nil }
	store.readPolyShareFn = func() ([]byte, error) { return marshalPrivShare(share), nil }

	conf := &Configuration{
		Key: hex.EncodeToString(crypto.PrivateKeyBytes(self)),
		Signers: []string{
			crypto.PublicKeyString(crypto.PublicKey(otherB)),
			crypto.PublicKeyString(crypto.PublicKey(self)),
			crypto.PublicKeyString(crypto.PublicKey(otherA)),
		},
	}

	node := NewNode(context.Background(), func() {}, store, &signerMessengerStub{}, conf)
	require.NotEmpty(checkedGroup)
	require.Equal(crypto.PrivateKeyBytes(self), crypto.PrivateKeyBytes(node.GetKey()))
	require.Len(node.GetSigners(), 3)
	require.Len(checkedGroup, 32)
	require.True(node.GetShare().V.Equal(share.V))
	require.Equal(share.I, node.GetShare().I)
	require.Len(node.GetPoly(), len(poly))
	for i := range poly {
		require.True(node.GetPoly()[i].Equal(poly[i]))
	}
	require.Equal(3, node.Threshold())
	require.True(node.signers[node.index].Public.Equal(crypto.PublicKey(self)))
}

func TestBoardPushAndIncomingChannels(t *testing.T) {
	require := require.New(t)

	msgs := &signerMessengerStub{}
	node := &Node{messenger: msgs, key: signerTestScalar()}
	board := node.NewBoard(context.Background(), 55)

	go func() { board.deals <- dkg.DealBundle{DealerIndex: 9} }()
	require.Equal(uint32(9), (<-board.IncomingDeal()).DealerIndex)

	go func() { board.resps <- dkg.ResponseBundle{ShareIndex: 8} }()
	require.Equal(uint32(8), (<-board.IncomingResponse()).ShareIndex)

	go func() { board.justs <- dkg.JustificationBundle{DealerIndex: 7} }()
	require.Equal(uint32(7), (<-board.IncomingJustification()).DealerIndex)

	deal := &dkg.DealBundle{DealerIndex: 1, SessionID: []byte("deal"), Signature: []byte("sig")}
	resp := &dkg.ResponseBundle{ShareIndex: 2, SessionID: []byte("resp"), Signature: []byte("sig")}
	just := &dkg.JustificationBundle{DealerIndex: 3, SessionID: []byte("just"), Signature: []byte("sig")}

	board.PushDeals(deal)
	board.PushResponses(resp)
	board.PushJustifications(just)

	require.Len(msgs.broadcasted, 3)

	msg, err := decodeMessage(msgs.broadcasted[0])
	require.NoError(err)
	require.Equal(MessageActionDKGDeal, msg.Action)
	nonce, decodedDeal, err := decodeDealBundle(msg.Data)
	require.NoError(err)
	require.Equal(uint64(55), nonce)
	require.Equal(deal.DealerIndex, decodedDeal.DealerIndex)

	msg, err = decodeMessage(msgs.broadcasted[1])
	require.NoError(err)
	require.Equal(MessageActionDKGResponse, msg.Action)
	decodedResp, err := decodeResponseBundle(msg.Data)
	require.NoError(err)
	require.Equal(resp.ShareIndex, decodedResp.ShareIndex)

	msg, err = decodeMessage(msgs.broadcasted[2])
	require.NoError(err)
	require.Equal(MessageActionDKGJustify, msg.Action)
	decodedJust, err := decodeJustificationBundle(msg.Data)
	require.NoError(err)
	require.Equal(just.DealerIndex, decodedJust.DealerIndex)
}

func TestHandleSetupMessageBranches(t *testing.T) {
	require := require.New(t)
	now := time.Now()

	err := (&Node{}).handleSetupMessage(context.Background(), &Message{Data: []byte{1, 2, 3}})
	require.Error(err)

	node := &Node{
		setupActions: map[string]*SetupBundle{"known": {Nonce: 10, Timestamp: now}},
		signers:      make([]dkg.Node, 2),
	}
	err = node.handleSetupMessage(context.Background(), &Message{
		Sender: "stale",
		Data:   encodeSetupBundle(&SetupBundle{Nonce: 9, Timestamp: now}),
	})
	require.NoError(err)
	require.NotContains(node.setupActions, "stale")

	node = &Node{
		setupActions: map[string]*SetupBundle{"known": {Nonce: 10, Timestamp: now}},
		signers:      make([]dkg.Node, 2),
	}
	err = node.handleSetupMessage(context.Background(), &Message{
		Sender: "expired",
		Data:   encodeSetupBundle(&SetupBundle{Nonce: 10, Timestamp: now.Add(6 * time.Minute)}),
	})
	require.NoError(err)
	require.NotContains(node.setupActions, "expired")

	node = &Node{
		setupActions: map[string]*SetupBundle{"old": {Nonce: 1, Timestamp: now}},
		signers:      make([]dkg.Node, 3),
	}
	err = node.handleSetupMessage(context.Background(), &Message{
		Sender: "new",
		Data:   encodeSetupBundle(&SetupBundle{Nonce: 2, Timestamp: now}),
	})
	require.NoError(err)
	require.NotContains(node.setupActions, "old")
	require.Contains(node.setupActions, "new")

	node = &Node{
		setupActions: make(map[string]*SetupBundle),
		signers:      make([]dkg.Node, 2),
		dkgStarted:   true,
	}
	err = node.handleSetupMessage(context.Background(), &Message{
		Sender: "peer",
		Data:   encodeSetupBundle(&SetupBundle{Nonce: 3, Timestamp: now}),
	})
	require.NoError(err)
	require.Contains(node.setupActions, "peer")
}

func TestMarshalHelpersRunDKGAndSetup(t *testing.T) {
	require := require.New(t)

	priv := &share.PriShare{I: 4, V: signerTestScalar()}
	encodedPriv := marshalPrivShare(priv)
	decodedPriv := unmarshalPrivShare(encodedPriv)
	require.Equal(priv.I, decodedPriv.I)
	require.Equal(crypto.PrivateKeyBytes(priv.V), crypto.PrivateKeyBytes(decodedPriv.V))

	commits := []kyber.Point{
		crypto.PublicKey(signerTestScalar()),
		crypto.PublicKey(signerTestScalar()),
	}
	encodedCommits := marshalCommitments(commits)
	decodedCommits := unmarshalCommitments(encodedCommits)
	require.Len(decodedCommits, len(commits))
	for i := range commits {
		require.True(decodedCommits[i].Equal(commits[i]))
	}
	require.Panics(func() {
		unmarshalCommitments(bytes.Repeat([]byte{1}, 128))
	})

	node := &Node{
		signers: []dkg.Node{
			{Index: 0, Public: crypto.PublicKey(signerTestScalar())},
			{Index: 1, Public: crypto.PublicKey(signerTestScalar())},
		},
		phaser: make(chan dkg.Phase, 1),
	}
	require.Equal(node.phaser, node.NextPhase())
	require.Equal(node.getNonce(9), node.getNonce(9))
	require.NotEqual(node.getNonce(9), node.getNonce(10))

	origWait := waitDKGResult
	origNewProtocol := newDKGProtocol
	origRunProtocol := runDKGProtocol
	t.Cleanup(func() {
		waitDKGResult = origWait
		newDKGProtocol = origNewProtocol
		runDKGProtocol = origRunProtocol
	})

	runNode := &Node{index: 1}
	waitDKGResult = func(*dkg.Protocol) <-chan dkg.OptionResult {
		ch := make(chan dkg.OptionResult, 1)
		ch <- dkg.OptionResult{Result: &dkg.Result{
			Key: &dkg.DistKeyShare{
				Commits: commits,
				Share:   &share.PriShare{I: 1, V: signerTestScalar()},
			},
		}}
		return ch
	}
	pub, shareBytes, err := runNode.runDKG(context.Background(), &dkg.Protocol{})
	require.NoError(err)
	require.Equal(marshalCommitments(commits), pub)
	require.NotEmpty(shareBytes)

	waitDKGResult = func(*dkg.Protocol) <-chan dkg.OptionResult {
		ch := make(chan dkg.OptionResult, 1)
		ch <- dkg.OptionResult{Error: errors.New("wait-end")}
		return ch
	}
	_, _, err = runNode.runDKG(context.Background(), &dkg.Protocol{})
	require.EqualError(err, "wait-end")

	waitDKGResult = func(*dkg.Protocol) <-chan dkg.OptionResult {
		ch := make(chan dkg.OptionResult, 1)
		ch <- dkg.OptionResult{Result: &dkg.Result{
			Key: &dkg.DistKeyShare{
				Commits: commits,
				Share:   &share.PriShare{I: 2, V: signerTestScalar()},
			},
		}}
		return ch
	}
	_, _, err = runNode.runDKG(context.Background(), &dkg.Protocol{})
	require.Error(err)
	require.Contains(err.Error(), "private share index malformed")

	setupStore := newSignerStoreStub()
	setupNode := &Node{dkgStarted: true, store: setupStore}
	require.NoError(setupNode.setup(context.Background(), 1))

	setupStore = newSignerStoreStub()
	setupStore.readPolyShareFn = func() ([]byte, error) { return nil, errors.New("read-share") }
	setupNode = &Node{store: setupStore}
	err = setupNode.setup(context.Background(), 1)
	require.EqualError(err, "read-share")

	setupStore = newSignerStoreStub()
	setupStore.readPolyShareFn = func() ([]byte, error) { return []byte("share"), nil }
	setupNode = &Node{store: setupStore}
	require.NoError(setupNode.setup(context.Background(), 1))

	setupStore = newSignerStoreStub()
	setupStore.readPolyPublicFn = func() ([]byte, error) { return nil, errors.New("read-public") }
	setupNode = &Node{store: setupStore}
	err = setupNode.setup(context.Background(), 1)
	require.EqualError(err, "read-public")

	setupStore = newSignerStoreStub()
	setupStore.readPolyPublicFn = func() ([]byte, error) { return []byte("public"), nil }
	setupNode = &Node{store: setupStore}
	require.NoError(setupNode.setup(context.Background(), 1))

	setupStore = newSignerStoreStub()
	setupNode = &Node{
		store:     setupStore,
		messenger: &signerMessengerStub{},
		key:       signerTestScalar(),
		signers:   []dkg.Node{{Index: 0, Public: crypto.PublicKey(signerTestScalar())}},
		phaser:    make(chan dkg.Phase, 1),
		dkgDone:   func() {},
	}
	newDKGProtocol = func(*dkg.Config, dkg.Board, dkg.Phaser, bool) (*dkg.Protocol, error) {
		return nil, errors.New("new-protocol")
	}
	err = setupNode.setup(context.Background(), 2)
	require.EqualError(err, "new-protocol")

	wrote := make(chan struct{}, 1)
	var wrotePub, wrotePriv []byte
	setupStore = newSignerStoreStub()
	setupStore.writePolyFn = func(pub, priv []byte) error {
		wrotePub = append([]byte(nil), pub...)
		wrotePriv = append([]byte(nil), priv...)
		wrote <- struct{}{}
		return nil
	}
	setupNode = &Node{
		store:     setupStore,
		messenger: &signerMessengerStub{},
		key:       signerTestScalar(),
		signers:   []dkg.Node{{Index: 0, Public: crypto.PublicKey(signerTestScalar())}},
		phaser:    make(chan dkg.Phase, 1),
		dkgDone:   func() {},
	}
	newDKGProtocol = func(*dkg.Config, dkg.Board, dkg.Phaser, bool) (*dkg.Protocol, error) {
		return &dkg.Protocol{}, nil
	}
	runDKGProtocol = func(*Node, context.Context, *dkg.Protocol) ([]byte, []byte, error) {
		return []byte("pub"), []byte("priv"), nil
	}
	err = setupNode.setup(context.Background(), 3)
	require.NoError(err)
	require.True(setupNode.dkgStarted)
	require.NotNil(setupNode.board)
	require.Equal(dkg.DealPhase, <-setupNode.phaser)
	select {
	case <-wrote:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for WritePoly")
	}
	require.Equal([]byte("pub"), wrotePub)
	require.Equal([]byte("priv"), wrotePriv)
}

func TestRunPaths(t *testing.T) {
	require := require.New(t)

	readyNode := &Node{share: &share.PriShare{I: 0, V: bn256.NewSuiteG2().Scalar()}}
	require.NoError(readyNode.Run(context.Background()))

	self := signerTestScalar()
	peer := signerTestScalar()
	selfPub := crypto.PublicKey(self)
	peerPub := crypto.PublicKey(peer)

	msgs := &signerMessengerStub{
		received: []receivedMessage{
			{body: []byte{1, 2, 3}},
			{body: MakeSetupMessage(context.Background(), signerTestScalar(), 1)},
			{body: MakeSetupMessage(context.Background(), peer, 2)},
			{body: makeMessage(peer, MessageActionDKGDeal, encodeDealBundle(&dkg.DealBundle{
				DealerIndex: 1,
				SessionID:   []byte("deal"),
				Signature:   []byte("sig"),
			}, 9))},
			{body: makeMessage(peer, MessageActionDKGResponse, encodeResponseBundle(&dkg.ResponseBundle{
				ShareIndex: 1,
				SessionID:  []byte("resp"),
				Signature:  []byte("sig"),
			}))},
			{body: makeMessage(peer, MessageActionDKGJustify, encodeJustificationBundle(&dkg.JustificationBundle{
				DealerIndex: 1,
				SessionID:   []byte("just"),
				Signature:   []byte("sig"),
			}))},
		},
	}

	node := &Node{
		messenger:    msgs,
		setupActions: make(map[string]*SetupBundle),
		dkgStarted:   true,
		board: &Board{
			deals: make(chan dkg.DealBundle, 1),
			resps: make(chan dkg.ResponseBundle, 1),
			justs: make(chan dkg.JustificationBundle, 1),
		},
		signers: []dkg.Node{
			{Index: 0, Public: selfPub},
			{Index: 1, Public: peerPub},
		},
		phaser: make(chan dkg.Phase, 3),
		key:    self,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- node.Run(ctx)
	}()

	require.Eventually(func() bool {
		return len(node.setupActions) == 1 &&
			len(node.board.deals) == 1 &&
			len(node.board.resps) == 1 &&
			len(node.board.justs) == 1 &&
			len(node.phaser) == 3
	}, time.Second, 10*time.Millisecond)

	require.Equal(uint32(1), (<-node.board.deals).DealerIndex)
	require.Equal(uint32(1), (<-node.board.resps).ShareIndex)
	require.Equal(uint32(1), (<-node.board.justs).DealerIndex)
	require.Equal(dkg.ResponsePhase, <-node.phaser)
	require.Equal(dkg.JustifPhase, <-node.phaser)
	require.Equal(dkg.FinishPhase, <-node.phaser)

	cancel()
	require.ErrorIs(<-errCh, messenger.ErrorDone)
}

func TestRunSkipsSetupAndBoardErrors(t *testing.T) {
	require := require.New(t)

	self := signerTestScalar()
	peer := signerTestScalar()
	msgs := &signerMessengerStub{
		received: []receivedMessage{
			{body: makeMessage(peer, MessageActionDKGDeal, encodeDealBundle(&dkg.DealBundle{
				DealerIndex: 1,
				SessionID:   []byte("deal"),
				Signature:   []byte("sig"),
			}, 5))},
			{body: makeMessage(peer, MessageActionDKGResponse, encodeResponseBundle(&dkg.ResponseBundle{
				ShareIndex: 1,
				SessionID:  []byte("resp"),
				Signature:  []byte("sig"),
			}))},
			{body: makeMessage(peer, MessageActionDKGJustify, encodeJustificationBundle(&dkg.JustificationBundle{
				DealerIndex: 1,
				SessionID:   []byte("just"),
				Signature:   []byte("sig"),
			}))},
		},
	}

	node := &Node{
		messenger: msgs,
		store: &signerStoreStub{
			checkPolyGroupFn: func([]byte) (bool, error) { return true, nil },
			readPolyPublicFn: func() ([]byte, error) { return nil, nil },
			readPolyShareFn:  func() ([]byte, error) { return nil, errors.New("read-share") },
			writePolyFn:      func([]byte, []byte) error { return nil },
		},
		setupActions: make(map[string]*SetupBundle),
		signers: []dkg.Node{
			{Index: 0, Public: crypto.PublicKey(self)},
			{Index: 1, Public: crypto.PublicKey(peer)},
		},
		phaser:  make(chan dkg.Phase, 1),
		key:     self,
		dkgDone: func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- node.Run(ctx)
	}()

	require.Eventually(func() bool {
		return len(msgs.received) == 0
	}, time.Second, 10*time.Millisecond)

	cancel()
	require.ErrorIs(<-errCh, messenger.ErrorDone)
	require.Nil(node.board)
	require.True(node.dkgStarted)
}

func TestNewNodePanicsForInvalidState(t *testing.T) {
	require := require.New(t)

	self := signerTestScalar()
	other := signerTestScalar()
	baseConf := &Configuration{
		Key: hex.EncodeToString(crypto.PrivateKeyBytes(self)),
		Signers: []string{
			crypto.PublicKeyString(crypto.PublicKey(self)),
			crypto.PublicKeyString(crypto.PublicKey(other)),
		},
	}

	require.Panics(func() {
		NewNode(context.Background(), func() {}, &signerStoreStub{
			checkPolyGroupFn: func([]byte) (bool, error) { return false, nil },
			readPolyPublicFn: func() ([]byte, error) { return nil, nil },
			readPolyShareFn:  func() ([]byte, error) { return nil, nil },
			writePolyFn:      func([]byte, []byte) error { return nil },
		}, &signerMessengerStub{}, baseConf)
	})

	require.Panics(func() {
		NewNode(context.Background(), func() {}, newSignerStoreStub(), &signerMessengerStub{}, &Configuration{
			Key:     hex.EncodeToString(crypto.PrivateKeyBytes(self)),
			Signers: []string{crypto.PublicKeyString(crypto.PublicKey(other))},
		})
	})
}
