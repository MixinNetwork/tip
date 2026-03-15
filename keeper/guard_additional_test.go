package keeper

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

type stubStore struct {
	readAssigneeFn        func([]byte) ([]byte, error)
	readAssignorFn        func([]byte) ([]byte, error)
	checkLimitFn          func([]byte, time.Duration, uint32, bool) (int, error)
	checkEphemeralNonceFn func([]byte, []byte, uint64, time.Duration) (bool, error)
	rotateEphemeralFn     func([]byte, []byte, uint64) error
	writeAssigneeFn       func([]byte, []byte) error
	watchFn               func([]byte) ([]byte, time.Time, int, error)
}

func newStubStore() *stubStore {
	return &stubStore{
		readAssigneeFn: func([]byte) ([]byte, error) { return nil, nil },
		readAssignorFn: func([]byte) ([]byte, error) { return nil, nil },
		checkLimitFn: func(_ []byte, _ time.Duration, quota uint32, _ bool) (int, error) {
			return int(quota), nil
		},
		checkEphemeralNonceFn: func([]byte, []byte, uint64, time.Duration) (bool, error) { return true, nil },
		rotateEphemeralFn:     func([]byte, []byte, uint64) error { return nil },
		writeAssigneeFn:       func([]byte, []byte) error { return nil },
		watchFn:               func([]byte) ([]byte, time.Time, int, error) { return nil, time.Time{}, 0, nil },
	}
}

func (*stubStore) CheckPolyGroup([]byte) (bool, error) { return false, nil }
func (*stubStore) ReadPolyPublic() ([]byte, error)     { return nil, nil }
func (*stubStore) ReadPolyShare() ([]byte, error)      { return nil, nil }
func (*stubStore) WritePoly([]byte, []byte) error      { return nil }
func (s *stubStore) WriteAssignee(key []byte, assignee []byte) error {
	return s.writeAssigneeFn(key, assignee)
}
func (s *stubStore) ReadAssignor(key []byte) ([]byte, error) { return s.readAssignorFn(key) }
func (s *stubStore) ReadAssignee(key []byte) ([]byte, error) { return s.readAssigneeFn(key) }
func (s *stubStore) CheckLimit(key []byte, window time.Duration, quota uint32, increase bool) (int, error) {
	return s.checkLimitFn(key, window, quota, increase)
}
func (s *stubStore) CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error) {
	return s.checkEphemeralNonceFn(key, ephemeral, nonce, grace)
}
func (s *stubStore) RotateEphemeralNonce(key, ephemeral []byte, nonce uint64) error {
	return s.rotateEphemeralFn(key, ephemeral, nonce)
}
func (*stubStore) WriteSignRequest([]byte, []byte) (time.Time, int, error) {
	return time.Time{}, 0, nil
}
func (s *stubStore) Watch(key []byte) ([]byte, time.Time, int, error) { return s.watchFn(key) }

func TestCheckAssigneeValidation(t *testing.T) {
	require := require.New(t)

	_, err := checkAssignee("zz")
	require.Error(err)
	require.Contains(err.Error(), "invalid assignee format")

	_, err = checkAssignee("abcd")
	require.Error(err)
	require.Contains(err.Error(), "invalid assignee format")

	invalidKey := append(bytes.Repeat([]byte{1}, 128), bytes.Repeat([]byte{2}, 64)...)
	_, err = checkAssignee(hex.EncodeToString(invalidKey))
	require.Error(err)
	require.Contains(err.Error(), "invalid assignee public key")

	user := bn256.NewSuiteBn256().Scalar().Pick(random.New())
	pub := crypto.PublicKey(user)
	assignee := crypto.PublicKeyBytes(pub)
	sig, err := crypto.Sign(user, assignee)
	require.NoError(err)

	valid := append(append([]byte{}, assignee...), sig...)
	decoded, err := checkAssignee(hex.EncodeToString(valid))
	require.NoError(err)
	require.Equal(valid, decoded)

	valid[len(valid)-1] ^= 0xff
	_, err = checkAssignee(hex.EncodeToString(valid))
	require.Error(err)
}

func TestCheckSignatureValidation(t *testing.T) {
	require := require.New(t)

	user := bn256.NewSuiteBn256().Scalar().Pick(random.New())
	pub := crypto.PublicKey(user)
	ephemeral := new(big.Int).SetBytes(bytes.Repeat([]byte{3}, 32))
	rotation := new(big.Int).SetBytes(bytes.Repeat([]byte{4}, 32))
	assignee := []byte("assignee")
	nonce := uint64(8)
	grace := uint64(EphemeralGracePeriod)

	msg := crypto.PublicKeyBytes(pub)
	msg = append(msg, bytes.Repeat([]byte{3}, 32)...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	msg = append(msg, bytes.Repeat([]byte{4}, 32)...)
	msg = append(msg, assignee...)

	sig, err := crypto.Sign(user, msg)
	require.NoError(err)
	require.NoError(checkSignature(pub, sig, ephemeral, rotation, nonce, grace, assignee))

	err = checkSignature(pub, sig, big.NewInt(0), rotation, nonce, grace, assignee)
	require.Error(err)
	require.Contains(err.Error(), "invalid ephemeral")
}

func TestGuardStoreErrorPaths(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteBn256()
	signer := suite.Scalar().Pick(random.New())
	node := crypto.PublicKey(signer)
	user := suite.Scalar().Pick(random.New())
	identity := crypto.PublicKeyString(crypto.PublicKey(user))
	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	watcher := bytes.Repeat([]byte{9}, 32)

	signature, data := makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 11, 1, "", "", hex.EncodeToString(watcher))

	store := newStubStore()
	var seenGrace time.Duration
	store.checkEphemeralNonceFn = func(_ []byte, _ []byte, _ uint64, grace time.Duration) (bool, error) {
		seenGrace = grace
		return true, nil
	}

	res, err := Guard(store, signer, identity, signature, data)
	require.NoError(err)
	require.NotNil(res)
	require.Equal(EphemeralGracePeriod, seenGrace)

	_, err = Guard(store, signer, "invalid", signature, data)
	require.Error(err)
	require.Contains(err.Error(), "invalid identity")

	_, err = Guard(store, signer, identity, "not-hex", data)
	require.Error(err)
	require.Contains(err.Error(), "invalid signature")

	store = newStubStore()
	store.readAssigneeFn = func([]byte) ([]byte, error) { return nil, fmt.Errorf("read-assignee") }
	_, err = Guard(store, signer, identity, signature, data)
	require.EqualError(err, "read-assignee")

	store = newStubStore()
	store.readAssignorFn = func([]byte) ([]byte, error) { return nil, fmt.Errorf("read-assignor") }
	_, err = Guard(store, signer, identity, signature, data)
	require.EqualError(err, "read-assignor")

	store = newStubStore()
	store.watchFn = func([]byte) ([]byte, time.Time, int, error) { return nil, time.Time{}, 0, fmt.Errorf("watch-error") }
	_, err = Guard(store, signer, identity, signature, data)
	require.Error(err)
	require.Contains(err.Error(), "watch")

	store = newStubStore()
	store.checkLimitFn = func(key []byte, _ time.Duration, quota uint32, increase bool) (int, error) {
		if bytes.HasSuffix(key, []byte("EPHEMERAL")) && !increase {
			return 0, fmt.Errorf("ephemeral-limit")
		}
		return int(quota), nil
	}
	res, err = Guard(store, signer, identity, signature, data)
	require.EqualError(err, "ephemeral-limit")
	require.NotNil(res)

	store = newStubStore()
	store.checkEphemeralNonceFn = func([]byte, []byte, uint64, time.Duration) (bool, error) {
		return false, fmt.Errorf("nonce-error")
	}
	_, err = Guard(store, signer, identity, signature, data)
	require.EqualError(err, "nonce-error")

	rotation := bytes.Repeat([]byte{8}, 32)
	rotSig, rotData := makeTestRequestWithAssigneeAndRotation(user, node, ephmr, rotation, 12, uint64(EphemeralGracePeriod), "", "", hex.EncodeToString(watcher))
	store = newStubStore()
	store.rotateEphemeralFn = func([]byte, []byte, uint64) error { return fmt.Errorf("rotate-error") }
	_, err = Guard(store, signer, identity, rotSig, rotData)
	require.EqualError(err, "rotate-error")

	assigneeUser := suite.Scalar().Pick(random.New())
	assignee := crypto.PublicKeyBytes(crypto.PublicKey(assigneeUser))
	assigneeSig, err := crypto.Sign(assigneeUser, assignee)
	require.NoError(err)
	assigneeHex := hex.EncodeToString(append(append([]byte{}, assignee...), assigneeSig...))
	assignSig, assignData := makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 13, uint64(EphemeralGracePeriod), assigneeHex, "", hex.EncodeToString(watcher))
	store = newStubStore()
	store.writeAssigneeFn = func([]byte, []byte) error { return fmt.Errorf("write-assignee") }
	_, err = Guard(store, signer, identity, assignSig, assignData)
	require.EqualError(err, "write-assignee")
}
