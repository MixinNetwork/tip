package api

import (
	"bytes"
	"context"
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
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
	"github.com/unrolled/render"
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
