package keeper

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestGuard(t *testing.T) {
	require := require.New(t)

	dir, _ := os.MkdirTemp("/tmp", "tip-keeper-test")
	conf := &store.BadgerConfiguration{Dir: dir}
	bs, _ := store.OpenBadger(context.Background(), conf)
	defer bs.Close()

	suite := bn256.NewSuiteBn256()
	signer := suite.Scalar().Pick(random.New())
	node := crypto.PublicKey(signer)
	user := suite.Scalar().Pick(random.New())
	userPub := crypto.PublicKey(user)
	identity := crypto.PublicKeyString(userPub)

	watcherSeed := make([]byte, 32)
	_, err := rand.Read(watcherSeed)
	require.Nil(err)

	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	epb := new(big.Int).SetBytes(ephmr).Bytes()
	grace := uint64(time.Hour * 24 * 128)
	for i := range uint64(10) {
		signature, data := makeTestRequest(user, node, ephmr, nil, 1024+i, grace)
		res, err := Guard(bs, signer, identity, signature, data)
		require.Nil(err)
		require.Equal(SecretLimitQuota, res.Available)
		require.Equal(1024+i, res.Nonce)
		key := crypto.PublicKeyBytes(crypto.PublicKey(user))
		lkey := append(key, "EPHEMERAL"...)
		available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
		require.Equal(EphemeralLimitQuota, available)
		require.Nil(err)
	}

	// data should be base64 RawURLEncoding and none blank
	signature, _ := makeTestRequest(user, node, ephmr, nil, 1024, grace)
	_, err = Guard(bs, signer, identity, signature, "")
	require.NotNil(err)

	// identity is not equal
	signature, data := makeTestRequestWithInvalidIdentity(user, node, ephmr, nil, 1039, grace, "", "", "")
	_, err = Guard(bs, signer, identity, signature, data)
	require.NotNil(err)
	require.Contains(err.Error(), "invalid identity ")

	// invalid nonce
	signature, data = makeTestRequest(user, node, ephmr, nil, 1024, grace)
	res, err := Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.Equal(EphemeralLimitQuota-1, res.Available)
	require.Nil(res.Watcher)
	key := crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey := append(key, "EPHEMERAL"...)
	available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	require.Equal(EphemeralLimitQuota-1, available)
	require.Nil(err)
	oas, _, counter, err := bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(0, counter)
	require.Nil(oas)

	// invalid encryption
	signature, data = makeTestRequest(user, crypto.PublicKey(user), ephmr, nil, 1034, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(res)
	require.Contains(err.Error(), "invalid json ")
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	require.Equal(EphemeralLimitQuota-1, available)
	require.Nil(err)

	// invalid ephemeral
	signature, data = makeTestRequest(user, node, crypto.PublicKeyBytes(node), nil, 1034, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	require.NotNil(err)
	require.Contains(err.Error(), "invalid ephemeral")
	require.Nil(res)
	signature, data = makeTestRequest(user, node, bytes.Repeat([]byte{1}, 29), nil, 1034, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.Equal(EphemeralLimitQuota-2, res.Available)
	require.Nil(res.Watcher)
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	require.Equal(EphemeralLimitQuota-2, available)
	require.Nil(err)

	// invalid signature
	for i := 1; i < 6; i++ {
		_, data = makeTestRequest(user, node, ephmr, nil, uint64(1033+i), grace)
		res, err := Guard(bs, signer, identity, hex.EncodeToString(ephmr), data)
		require.Nil(err)
		require.Equal(res.Available, SecretLimitQuota-i)
		require.Nil(res.Watcher)
		key = crypto.PublicKeyBytes(crypto.PublicKey(user))
		lkey = append(key, "EPHEMERAL"...)
		available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
		require.Equal(EphemeralLimitQuota-2, available)
		require.Nil(err)
		lkey = append(key, "SECRET"...)
		available, err = bs.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
		require.Equal(SecretLimitQuota-i, available)
		require.Nil(err)
	}

	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1039, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.Equal(SecretLimitQuota-5, res.Available)
	require.Equal(uint64(1039), res.Nonce)
	require.NotNil(res.Watcher)
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	require.Equal(EphemeralLimitQuota-2, available)
	require.Nil(err)
	lkey = append(key, "SECRET"...)
	available, err = bs.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
	require.Equal(SecretLimitQuota-5, available)
	require.Nil(err)

	// invalid assignee
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1039, grace, identity, "", "")
	_, err = Guard(bs, signer, identity, signature, data)
	require.NotNil(err)
	require.Contains(err.Error(), "invalid assignee ")
	// valid assignee
	assignee := crypto.PublicKeyBytes(userPub)
	sig, err := crypto.Sign(user, assignee)
	require.Nil(err)
	assignee = append(assignee, sig...)
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1039, grace, hex.EncodeToString(assignee), "", "")
	res, err = Guard(bs, signer, identity, signature, data)
	require.Contains(err.Error(), "invalid watcher ")
	require.Nil(res)
	assignee = crypto.PublicKeyBytes(userPub)
	sig, err = crypto.Sign(user, assignee)
	require.Nil(err)
	assignee = append(assignee, sig...)
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1040, grace, hex.EncodeToString(assignee), "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.NotNil(res)
	_, counter, err = bs.WriteSignRequest(res.Assignor, res.Watcher)
	require.Nil(err)
	require.Equal(1, counter)
	assignee, err = bs.ReadAssignee(crypto.PublicKeyBytes(userPub))
	require.Nil(err)
	require.Len(assignee, 128)
	valid, err := bs.CheckEphemeralNonce(crypto.PublicKeyBytes(userPub), epb, 1040, time.Duration(grace))
	require.Nil(err)
	require.False(valid)
	valid, err = bs.CheckEphemeralNonce(crypto.PublicKeyBytes(userPub), epb, 1041, time.Duration(grace))
	require.Nil(err)
	require.True(valid)
	oas, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(1, counter)
	require.Equal(oas, crypto.PublicKeyBytes(userPub))
	// valid existing assignee counter + 1
	assignee = crypto.PublicKeyBytes(userPub)
	sig, err = crypto.Sign(user, assignee)
	require.Nil(err)
	assignee = append(assignee, sig...)
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1042, grace, hex.EncodeToString(assignee), "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.Equal(SecretLimitQuota-5, res.Available)
	require.NotNil(res.Watcher)
	_, counter, err = bs.WriteSignRequest(res.Assignor, res.Watcher)
	require.Nil(err)
	require.Equal(2, counter)
	assignee, err = bs.ReadAssignee(crypto.PublicKeyBytes(userPub))
	require.Nil(err)
	require.Len(assignee, 128)
	valid, err = bs.CheckEphemeralNonce(crypto.PublicKeyBytes(userPub), epb, 1042, time.Duration(grace))
	require.Nil(err)
	require.False(valid)
	valid, err = bs.CheckEphemeralNonce(crypto.PublicKeyBytes(userPub), epb, 1043, time.Duration(grace))
	require.Nil(err)
	require.True(valid)
	oas, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(2, counter)
	require.Equal(oas, crypto.PublicKeyBytes(userPub))
	// valid new assignee counter + 1
	newUser := suite.Scalar().Pick(random.New())
	newUserPub := crypto.PublicKey(newUser)
	newIdentity := crypto.PublicKeyString(newUserPub)
	assignee = crypto.PublicKeyBytes(newUserPub)
	sig, err = crypto.Sign(newUser, assignee)
	require.Nil(err)
	assignee = append(assignee, sig...)
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1045, grace, hex.EncodeToString(assignee), "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.NotNil(res)
	// test user pin
	signature, data = makeTestRequestWithAssigneeAndRotation(newUser, node, ephmr, nil, 1046, grace, "", "", hex.EncodeToString(watcherSeed))
	resNew, err := Guard(bs, signer, newIdentity, signature, data)
	require.Nil(err)
	require.NotNil(resNew)
	require.Equal(res.Assignor, resNew.Assignor)
	_, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(3, counter)
	_, counter, err = bs.WriteSignRequest(res.Assignor, res.Watcher)
	require.Nil(err)
	require.Equal(3, counter)
	_, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(3, counter)
	// test user old pin
	signature, data = makeTestRequestWithAssigneeAndRotation(user, node, ephmr, nil, 1047, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, identity, signature, data)
	require.Nil(err)
	require.Nil(res.Watcher)
	require.Equal(SecretLimitQuota-6, res.Available)
	// test invalid watcher identity
	invalidUser := suite.Scalar().Pick(random.New())
	invalidUserPub := crypto.PublicKey(invalidUser)
	invalidIdentity := crypto.PublicKeyString(invalidUserPub)
	signature, data = makeTestRequestWithAssigneeAndRotation(invalidUser, node, ephmr, nil, 1047, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, invalidIdentity, signature, data)
	require.Nil(err)
	require.Nil(res.Watcher)
	require.Equal(SecretLimitQuota-7, res.Available)
	oas, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(3, counter)
	require.Equal(oas, crypto.PublicKeyBytes(userPub))
	signature, data = makeTestRequestWithAssigneeAndRotation(newUser, node, ephmr, nil, 1048, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, newIdentity, signature, data)
	require.Nil(err)
	require.NotNil(res.Watcher)
	require.Equal(SecretLimitQuota-7, res.Available)
	signature, data = makeTestRequestWithAssigneeAndRotation(invalidUser, node, ephmr, nil, 1050, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, invalidIdentity, signature, data)
	require.Nil(err)
	require.Nil(res.Watcher)
	require.Equal(SecretLimitQuota-8, res.Available)
	signature, data = makeTestRequestWithAssigneeAndRotation(newUser, node, ephmr, nil, 1051, grace, "", "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, newIdentity, signature, data)
	require.Nil(err)
	require.NotNil(res.Watcher)
	require.Equal(SecretLimitQuota-8, res.Available)
	oas, _, counter, err = bs.Watch(watcherSeed)
	require.Nil(err)
	require.Equal(3, counter)
	require.Equal(oas, crypto.PublicKeyBytes(userPub))
	// setup li pin
	liWatcher := make([]byte, 32)
	_, err = rand.Read(liWatcher)
	require.Nil(err)
	li := suite.Scalar().Pick(random.New())
	liPub := crypto.PublicKey(li)
	liIdentity := crypto.PublicKeyString(liPub)
	signature, data = makeTestRequestWithAssigneeAndRotation(li, node, ephmr, nil, 100, grace, "", "", hex.EncodeToString(liWatcher))
	res, err = Guard(bs, signer, liIdentity, signature, data)
	require.Nil(err)
	require.NotNil(res)
	// update li' pin with wrong assignee
	signature, data = makeTestRequestWithAssigneeAndRotation(li, node, ephmr, nil, 105, grace, hex.EncodeToString(assignee), "", hex.EncodeToString(liWatcher))
	_, err = Guard(bs, signer, liIdentity, signature, data)
	require.NotNil(err)
	require.Contains(err.Error(), "invalid assignor as is assignee")
	// update li pin
	liNew := suite.Scalar().Pick(random.New())
	liNewPub := crypto.PublicKey(liNew)
	liNewIdentity := crypto.PublicKeyString(liNewPub)
	assignee = crypto.PublicKeyBytes(liNewPub)
	sig, err = crypto.Sign(liNew, assignee)
	require.Nil(err)
	assignee = append(assignee, sig...)
	signature, data = makeTestRequestWithAssigneeAndRotation(li, node, ephmr, nil, 110, grace, hex.EncodeToString(assignee), "", hex.EncodeToString(watcherSeed))
	res, err = Guard(bs, signer, liIdentity, signature, data)
	require.Nil(err)
	require.NotNil(res)
	// test li pin
	signature, data = makeTestRequestWithAssigneeAndRotation(liNew, node, ephmr, nil, 115, grace, "", "", hex.EncodeToString(liWatcher))
	res, err = Guard(bs, signer, liNewIdentity, signature, data)
	require.Nil(err)
	require.NotNil(res)
	// pin should have watcher
	signature, data = makeTestRequestWithAssigneeAndRotation(liNew, node, ephmr, nil, 117, grace, "", "", "")
	res, err = Guard(bs, signer, liNewIdentity, signature, data)
	require.Contains(err.Error(), "invalid watcher ")
	require.Nil(res)
	// invalid ephmr
	ephmr = crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	signature, data = makeTestRequestWithAssigneeAndRotation(liNew, node, ephmr, nil, 119, grace, "", "", hex.EncodeToString(liWatcher))
	res, err = Guard(bs, signer, liNewIdentity, signature, data)
	require.Nil(err)
	require.Equal(EphemeralLimitQuota-1, res.Available)
	require.Nil(res.Watcher)
}

func TestAssigneeAndRotation(t *testing.T) {
	require := require.New(t)

	dir, _ := os.MkdirTemp("/tmp", "tip-keeper-test")
	conf := &store.BadgerConfiguration{Dir: dir}
	bs, _ := store.OpenBadger(context.Background(), conf)
	defer bs.Close()

	suite := bn256.NewSuiteBn256()
	signer := suite.Scalar().Pick(random.New())
	node := crypto.PublicKey(signer)

	u1 := suite.Scalar().Pick(random.New())
	i1 := crypto.PublicKeyString(crypto.PublicKey(u1))
	u2 := suite.Scalar().Pick(random.New())
	i2 := crypto.PublicKeyString(crypto.PublicKey(u2))
	u3 := suite.Scalar().Pick(random.New())
	i3 := crypto.PublicKeyString(crypto.PublicKey(u3))

	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace := uint64(time.Hour * 24 * 128)
	signature, data := makeTestRequest(u1, node, ephmr, nil, 1024, grace)
	res, err := Guard(bs, signer, i1, signature, data)
	require.Nil(err)
	require.Equal(SecretLimitQuota, res.Available)
	require.Equal(1024, int(res.Nonce))

	ephmr = crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace = uint64(time.Hour * 24 * 128)
	signature, data = makeTestRequest(u2, node, ephmr, nil, 1024, grace)
	res, err = Guard(bs, signer, i2, signature, data)
	require.Nil(err)
	require.Equal(SecretLimitQuota, res.Available)
	require.Equal(1024, int(res.Nonce))

	ephmr = crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace = uint64(time.Hour * 24 * 128)
	signature, data = makeTestRequest(u3, node, ephmr, nil, 1024, grace)
	res, err = Guard(bs, signer, i3, signature, data)
	require.Nil(err)
	require.Equal(SecretLimitQuota, res.Available)
	require.Equal(1024, int(res.Nonce))
}

func makeTestRequest(user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64) (string, string) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}
	return makeTestRequestWithAssigneeAndRotation(user, signer, ephmr, rtt, nonce, grace, "", "", hex.EncodeToString(seed))
}

func makeTestRequestWithAssigneeAndRotation(user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64, assignee, rotation, watcher string) (string, string) {
	logger.Debugf("rotation not tested %s", rotation)
	pkey := crypto.PublicKey(user)
	msg := crypto.PublicKeyBytes(pkey)
	msg = append(msg, ephmr...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	data := map[string]any{
		"identity":  crypto.PublicKeyString(pkey),
		"ephemeral": hex.EncodeToString(ephmr),
		"nonce":     nonce,
		"grace":     grace,
		"watcher":   watcher,
	}
	if rtt != nil {
		msg = append(msg, rtt[:]...)
		data["rotate"] = hex.EncodeToString(rtt)
	}
	if assignee != "" {
		buf, _ := hex.DecodeString(assignee)
		msg = append(msg, buf...)
		data["assignee"] = assignee
	}
	b, _ := json.Marshal(data)
	cipher := crypto.EncryptECDH(signer, user, b)
	sig, _ := crypto.Sign(user, msg)
	return hex.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(cipher[:])
}

func makeTestRequestWithInvalidIdentity(user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64, assignee, rotation, watcher string) (string, string) {
	logger.Debugf("rotation and assignee not tested %s %s", rotation, assignee)
	pkey := crypto.PublicKey(user)
	msg := crypto.PublicKeyBytes(pkey)
	msg = append(msg, ephmr...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	suite := bn256.NewSuiteBn256()
	intruder := suite.Scalar().Pick(random.New())
	intruderPub := crypto.PublicKey(intruder)
	data := map[string]any{
		"identity":  crypto.PublicKeyString(intruderPub),
		"ephemeral": hex.EncodeToString(ephmr),
		"nonce":     nonce,
		"grace":     grace,
		"watcher":   watcher,
	}
	if rtt != nil {
		msg = append(msg, rtt[:]...)
		data["rotate"] = hex.EncodeToString(rtt)
	}
	b, _ := json.Marshal(data)
	cipher := crypto.EncryptECDH(signer, user, b)
	sig, _ := crypto.Sign(user, msg)
	return hex.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(cipher[:])
}
