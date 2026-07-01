package api

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/keeper"
	"github.com/MixinNetwork/tip/store"
	"github.com/stretchr/testify/require"
	"github.com/unrolled/render"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/share"
	"go.dedis.ch/kyber/v4/util/random"
)

type signStoreStub struct {
	readAssigneeFn        func([]byte) ([]byte, error)
	readAssignorFn        func([]byte) ([]byte, error)
	checkLimitFn          func([]byte, time.Duration, uint32, bool) (int, error)
	checkEphemeralNonceFn func([]byte, []byte, uint64, time.Duration) (bool, error)
	rotateEphemeralFn     func([]byte, []byte, uint64) error
	writeSignRequestFn    func([]byte, []byte) (time.Time, int, error)
	watchFn               func([]byte) ([]byte, time.Time, int, error)
	writeAssigneeFn       func([]byte, []byte) error
}

func newSignStoreStub() *signStoreStub {
	return &signStoreStub{
		readAssigneeFn: func([]byte) ([]byte, error) { return nil, nil },
		readAssignorFn: func([]byte) ([]byte, error) { return nil, nil },
		checkLimitFn: func(_ []byte, _ time.Duration, quota uint32, _ bool) (int, error) {
			return int(quota), nil
		},
		checkEphemeralNonceFn: func([]byte, []byte, uint64, time.Duration) (bool, error) { return true, nil },
		rotateEphemeralFn:     func([]byte, []byte, uint64) error { return nil },
		writeSignRequestFn:    func([]byte, []byte) (time.Time, int, error) { return time.Unix(1700000100, 0), 1, nil },
		watchFn:               func([]byte) ([]byte, time.Time, int, error) { return nil, time.Time{}, 0, nil },
		writeAssigneeFn:       func([]byte, []byte) error { return nil },
	}
}

func (*signStoreStub) CheckPolyGroup([]byte) (bool, error) { return false, nil }
func (*signStoreStub) ReadPolyPublic() ([]byte, error)     { return nil, nil }
func (*signStoreStub) ReadPolyShare() ([]byte, error)      { return nil, nil }
func (*signStoreStub) WritePoly([]byte, []byte) error      { return nil }
func (s *signStoreStub) WriteAssignee(key []byte, assignee []byte) error {
	return s.writeAssigneeFn(key, assignee)
}
func (s *signStoreStub) ReadAssignor(key []byte) ([]byte, error) { return s.readAssignorFn(key) }
func (s *signStoreStub) ReadAssignee(key []byte) ([]byte, error) { return s.readAssigneeFn(key) }
func (s *signStoreStub) CheckLimit(key []byte, window time.Duration, quota uint32, increase bool) (int, error) {
	return s.checkLimitFn(key, window, quota, increase)
}
func (s *signStoreStub) CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error) {
	return s.checkEphemeralNonceFn(key, ephemeral, nonce, grace)
}
func (s *signStoreStub) RotateEphemeralNonce(key, ephemeral []byte, nonce uint64) error {
	return s.rotateEphemeralFn(key, ephemeral, nonce)
}
func (s *signStoreStub) WriteSignRequest(key, watcher []byte) (time.Time, int, error) {
	return s.writeSignRequestFn(key, watcher)
}
func (s *signStoreStub) Watch(key []byte) ([]byte, time.Time, int, error) { return s.watchFn(key) }

func openAPIBadger(t *testing.T) *store.BadgerStorage {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "tip-api-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	bs, err := store.OpenBadger(context.Background(), &store.BadgerConfiguration{Dir: dir})
	require.NoError(t, err)
	t.Cleanup(bs.Close)
	return bs
}

func makeAPISignRequest(user kyber.Scalar, signer kyber.Point, ephmr, rotate []byte, nonce, grace uint64, assignee, watcher string) *SignRequest {
	pub := crypto.PublicKey(user)
	msg := crypto.PublicKeyBytes(pub)
	msg = append(msg, ephmr...)

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)

	payload := map[string]any{
		"identity":  crypto.PublicKeyString(pub),
		"ephemeral": hex.EncodeToString(ephmr),
		"nonce":     nonce,
		"grace":     grace,
		"watcher":   watcher,
	}
	if len(rotate) > 0 {
		msg = append(msg, rotate...)
		payload["rotate"] = hex.EncodeToString(rotate)
	}
	if assignee != "" {
		ab, _ := hex.DecodeString(assignee)
		msg = append(msg, ab...)
		payload["assignee"] = assignee
	}

	data, _ := json.Marshal(payload)
	cipher := crypto.EncryptECDH(signer, user, data)
	sig, _ := crypto.Sign(user, msg)

	return &SignRequest{
		Action:    "SIGN",
		Watcher:   watcher,
		Identity:  crypto.PublicKeyString(pub),
		Signature: hex.EncodeToString(sig),
		Data:      base64.RawURLEncoding.EncodeToString(cipher),
	}
}

func TestNewServerAndHandlePanic(t *testing.T) {
	require := require.New(t)

	server := NewServer(&stubStore{}, &Configuration{Port: 7001})
	require.Equal(":7001", server.Addr)
	require.Equal(10*time.Second, server.ReadTimeout)
	require.Equal(10*time.Second, server.WriteTimeout)
	require.Equal(120*time.Second, server.IdleTimeout)
	require.NotNil(server.Handler)

	func() {
		defer handlePanic(nil, nil)
		panic("boom")
	}()
}

func TestSignSuccess(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteBn256()
	serverKey := suite.Scalar().Pick(random.New())
	serverPub := crypto.PublicKey(serverKey)
	user := suite.Scalar().Pick(random.New())
	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	watcher := bytes.Repeat([]byte{0x13}, 32)
	req := makeAPISignRequest(user, serverPub, ephmr, nil, 21, uint64(keeper.EphemeralGracePeriod), "", hex.EncodeToString(watcher))
	priv := &share.PriShare{I: 0, V: suite.Scalar().Pick(random.New())}

	bs := openAPIBadger(t)
	data, sigHex, err := sign(serverKey, bs, req, priv)
	require.NoError(err)

	payload, err := json.Marshal(data)
	require.NoError(err)
	sig, err := hex.DecodeString(sigHex)
	require.NoError(err)
	require.NoError(crypto.Verify(serverPub, payload, sig))

	body := data.(map[string]any)
	cipher, err := hex.DecodeString(body["cipher"].(string))
	require.NoError(err)

	plain := crypto.DecryptECDH(serverPub, user, cipher)
	require.Greater(len(plain), 8+128+8+8)
	require.Equal(uint64(21), binary.BigEndian.Uint64(plain[:8]))

	assignorOffset := len(plain) - (128 + 8 + 8)
	require.Equal(crypto.PublicKeyBytes(crypto.PublicKey(user)), plain[assignorOffset:assignorOffset+128])
	require.False(time.Unix(0, int64(binary.BigEndian.Uint64(plain[assignorOffset+128:assignorOffset+136]))).IsZero())
	require.Equal(uint64(1), binary.BigEndian.Uint64(plain[assignorOffset+136:]))
}

func TestSignMatchesLegacyKyberFixture(t *testing.T) {
	require := require.New(t)

	const (
		serverKeyHex = "1d86753d770a1ced1103edb2ffd11728ee4ab6aed41094732c1748c72f2e181d"
		userKeyHex   = "8bee954d5315684caa46d78fb8456a165bdd0cb44643d335a6b15c21d8c1872b"
		shareHex     = "000000030e296d4c585d3aca61ebaf6a0e56ec11288baf0ab2b659d78a7b661a782fe092"
		ephemeralHex = "2b5a6b0cb9576ea218d081baa14d2cea82a6839165a29b3bdfc6ef8582b0ce5a"
		watcherHex   = "2b5a6b0cb9576ea218d081baa14d2cea82a6839165a29b3bdfc6ef8582b0ce5a"

		legacyRequestIdentity   = "5JmMpYk6NEw3uMzciJ99iTpA9m5oLw3c8ocXd29CphTfdwc45FH3SFXYXKKATQqoF6FQHfCS9jZmSPpPbRuB1sj61QU2NxZ4388NVuXhXLLXfFp9gfKHSTtkGnSdsz8JyeZ3fKHD5ni8QVXXHkuftMdvkPswT2VmnyaMuRv3Dddt2sNk4EF3LL"
		legacyRequestSignature  = "63abc17b385815e0636e690e582184bccdfbf64cc124828ce77964dfc0a174fb5756021009e35d30954f15ab923c9793e7f109a0c2f23a7e08da4fe58d93e3ee"
		legacyRequestData       = "AAECAwQFBgcICQoL6WEvq0fOzUj9nxQTHRPzgwrEOk_n0VEjb6SAvDvhpZ-xStL3ki2iVh-DRyA570SZTl7tPacABMcVpXN6eMhjyU1p9iqjAOPid8oIVdS6xmq5N7OcNdtayngyHbWpKlERMh1_M_MCOxJV4xLg7tamdG5cdc9UBE5LItT-VmvxCrCyCOBQFZDqCiBF7Vhk9D8pzy9s147Zd9W1vJEPYquY_f1WPuXBnN5SpFn7e6zP1hbFssFZQtky_wmSBFtmN8dqvcyrIOH86gfivxUtGDSr5LjH3TV7DvOZfUqp43Ei4hPPlKHMSocoGHjYNhF3N58AggxsrLeLMW4Q77q4JQWd0HNaoZ3ugPjiyqlOnV5u9t1bZlPuhGSG9_4MCdpjHh_nJDrxgVIor9byghX_4Gd-bqxc21s6POUqB6yddyKS564nQX2h-SrgVHg7q5tFIDkM7vQT-wSd8nY763j4pt3d46qXCcnmFhWOcxukaFUhRy5NooVEBswtbY3sO5GxkV7MaQMu-znw4_FKpDtDJKfM-6-z0m7vFEby"
		legacyResponseCipher    = "101112131415161718191a1b945842ae16cb61ef53e877257e70603814ed2f7aafe2acdc0b6a17dc7ea3bb017a5273a5df9e682444582718d8d1d9665a28f63ce07c14debc5bd0334653c28d7bae1d6dd71812ea84e971b05e6aecbddb39eb1cfff3b6bce8daa9c09e6a53714cd7f1f9f5c7a7d2c75e2b922abc19814390c9e09ad0094056c1a6d8636164e8b745ec6cb42c5fbe3d7dc7d71c55e507df3834b7b6b352285f52ca5cf8d978f2a201b70a506f8ba6fe5014d3a66929cc20886f79f14ddf0062d6afc7d66ab3b3dff58c9f2e7a69ee707ba0c10118d1179ec64bb84e462477f11b4e0bf28d4a25e8de03110b49c8ea4955"
		legacyResponseSignature = "7aba122edfcb613222322591ec133db26bcb5e70137334ce170d4b3baf72c79c676deb1b6146aa19caa6883b1dd50379ef8614e8f18c6078a68c15573bfbd18e"
		legacyResponsePlain     = "00000000000004d200033e110b613b00caea0e0918da2f657595d749341a3c59f49b6163d64d3ed085271d939fe87abe13c16f892fcf4ea4e87c5b795e3983603ef5c7d6b0c1ed3095ad81e40f672aaf99d6a698ff4c57e2cc8ca9d15c1b295baff02de4569fa70ab21e44ec5aaa20c790ece45396c9124094c0ba4933e2bd6e9739ec7d9f74d6dfd8f529fe0e728169ee71856a62f59421a9a71b3426b817ca5c6ecac6b5e274dc0fef5b725833ebca07180a8031e9b44bcd1e852a017d6f4d85044af0e419f65bf3b117979d157ea0e87b0000000000000007"
	)

	nonceBytes, err := hex.DecodeString("000102030405060708090a0b101112131415161718191a1b")
	require.NoError(err)
	oldReader := crand.Reader
	crand.Reader = bytes.NewReader(nonceBytes)
	t.Cleanup(func() {
		crand.Reader = oldReader
	})

	serverKey, err := crypto.PrivateKeyFromHex(serverKeyHex)
	require.NoError(err)
	serverPub := crypto.PublicKey(serverKey)
	user, err := crypto.PrivateKeyFromHex(userKeyHex)
	require.NoError(err)
	ephmr, err := hex.DecodeString(ephemeralHex)
	require.NoError(err)

	req := makeAPISignRequest(user, serverPub, ephmr, nil, 1234, uint64(keeper.EphemeralGracePeriod), "", watcherHex)
	require.Equal(legacyRequestIdentity, req.Identity)
	require.Equal(legacyRequestSignature, req.Signature)
	require.Equal(legacyRequestData, req.Data)

	shareBytes, err := hex.DecodeString(shareHex)
	require.NoError(err)
	priv := &share.PriShare{
		I: binary.BigEndian.Uint32(shareBytes[:4]),
		V: bn256.NewSuiteG2().Scalar().SetBytes(shareBytes[4:]),
	}
	store := newSignStoreStub()
	store.writeSignRequestFn = func(assignor, watcher []byte) (time.Time, int, error) {
		require.Equal(crypto.PublicKeyBytes(crypto.PublicKey(user)), assignor)
		require.Equal(ephmr, watcher)
		return time.Unix(1700000100, 123), 7, nil
	}

	data, sigHex, err := sign(serverKey, store, req, priv)
	require.NoError(err)
	require.Equal(legacyResponseSignature, sigHex)

	body := data.(map[string]any)
	require.Equal(legacyResponseCipher, body["cipher"])

	payload, err := json.Marshal(data)
	require.NoError(err)
	sig, err := hex.DecodeString(sigHex)
	require.NoError(err)
	require.NoError(crypto.Verify(serverPub, payload, sig))

	cipher, err := hex.DecodeString(body["cipher"].(string))
	require.NoError(err)
	plain := crypto.DecryptECDH(serverPub, user, cipher)
	require.Equal(legacyResponsePlain, hex.EncodeToString(plain))
	require.Equal(uint64(1234), binary.BigEndian.Uint64(plain[:8]))
	require.Equal(uint64(7), binary.BigEndian.Uint64(plain[len(plain)-8:]))
}

func TestSignMapsErrors(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteBn256()
	serverKey := suite.Scalar().Pick(random.New())
	serverPub := crypto.PublicKey(serverKey)
	user := suite.Scalar().Pick(random.New())
	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	watcher := bytes.Repeat([]byte{0x17}, 32)
	req := makeAPISignRequest(user, serverPub, ephmr, nil, 22, uint64(keeper.EphemeralGracePeriod), "", hex.EncodeToString(watcher))
	priv := &share.PriShare{I: 0, V: suite.Scalar().Pick(random.New())}
	assignor := crypto.PublicKeyBytes(crypto.PublicKey(user))

	store := newSignStoreStub()
	store.checkLimitFn = func(key []byte, _ time.Duration, quota uint32, increase bool) (int, error) {
		if bytes.HasSuffix(key, []byte("SECRET")) && !increase {
			return 0, nil
		}
		return int(quota), nil
	}
	_, _, err := sign(serverKey, store, req, priv)
	require.ErrorIs(err, ErrTooManyRequest)

	store = newSignStoreStub()
	store.watchFn = func([]byte) ([]byte, time.Time, int, error) {
		return []byte("other-assignor"), time.Unix(1700000200, 0), 1, nil
	}
	store.checkLimitFn = func(_ []byte, _ time.Duration, _ uint32, _ bool) (int, error) {
		return 3, nil
	}
	_, _, err = sign(serverKey, store, req, priv)
	require.ErrorIs(err, ErrInvalidAssignor)

	store = newSignStoreStub()
	store.writeSignRequestFn = func(gotAssignor, gotWatcher []byte) (time.Time, int, error) {
		require.Equal(assignor, gotAssignor)
		require.Equal(watcher, gotWatcher)
		return time.Time{}, 0, fmt.Errorf("write-sign-request")
	}
	_, _, err = sign(serverKey, store, req, priv)
	require.ErrorIs(err, ErrUnknown)
}

func TestHandleSignStatusMappings(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteBn256()
	serverKey := suite.Scalar().Pick(random.New())
	serverPub := crypto.PublicKey(serverKey)
	user := suite.Scalar().Pick(random.New())
	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	watcher := bytes.Repeat([]byte{0x19}, 32)
	reqBody := makeAPISignRequest(user, serverPub, ephmr, nil, 23, uint64(keeper.EphemeralGracePeriod), "", hex.EncodeToString(watcher))
	data, err := json.Marshal(reqBody)
	require.NoError(err)

	makeRequest := func(store store.Storage) *httptest.ResponseRecorder {
		hdr := &Handler{
			store: store,
			conf: &Configuration{
				Key:   serverKey,
				Share: &share.PriShare{I: 0, V: suite.Scalar().Pick(random.New())},
			},
			render: render.New(),
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
		hdr.ServeHTTP(rec, req)
		return rec
	}

	bs := openAPIBadger(t)
	require.Equal(http.StatusOK, makeRequest(bs).Code)

	tooMany := newSignStoreStub()
	tooMany.checkLimitFn = func(key []byte, _ time.Duration, quota uint32, increase bool) (int, error) {
		if bytes.HasSuffix(key, []byte("SECRET")) && !increase {
			return 0, nil
		}
		return int(quota), nil
	}
	require.Equal(http.StatusTooManyRequests, makeRequest(tooMany).Code)

	forbidden := newSignStoreStub()
	forbidden.watchFn = func([]byte) ([]byte, time.Time, int, error) {
		return []byte("other-assignor"), time.Unix(1700000200, 0), 1, nil
	}
	forbidden.checkLimitFn = func(_ []byte, _ time.Duration, _ uint32, _ bool) (int, error) {
		return 2, nil
	}
	require.Equal(http.StatusForbidden, makeRequest(forbidden).Code)

	unknown := newSignStoreStub()
	unknown.writeSignRequestFn = func([]byte, []byte) (time.Time, int, error) {
		return time.Time{}, 0, fmt.Errorf("boom")
	}
	require.Equal(http.StatusInternalServerError, makeRequest(unknown).Code)
}
