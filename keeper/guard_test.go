package keeper

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/crypto/en256"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/assert"
)

func TestGuard(t *testing.T) {
	assert := assert.New(t)

	dir, _ := os.MkdirTemp("/tmp", "tip-keeper-test")
	conf := &store.BadgerConfiguration{Dir: dir}
	bs, _ := store.OpenBadger(context.Background(), conf)
	defer bs.Close()

	suite := en256.NewSuiteBn256()
	signer := suite.Scalar().Pick(random.New())
	node := crypto.PublicKey(signer)
	user := suite.Scalar().Pick(random.New())
	identity := crypto.PublicKeyString(crypto.PublicKey(user))

	ephmr := crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace := uint64(time.Hour * 24 * 128)
	for i := uint64(0); i < 10; i++ {
		signature, data := makeTestRequest(user, node, ephmr, nil, 1024+i, grace)
		res, err := Guard(bs, signer, identity, signature, data)
		assert.Nil(err)
		assert.Equal(SecretLimitQuota, res.Available)
		assert.Equal(1024+i, res.Nonce)
		key := crypto.PublicKeyBytes(crypto.PublicKey(user))
		lkey := append(key, "EPHEMERAL"...)
		available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
		assert.Equal(EphemeralLimitQuota, available)
		assert.Nil(err)
	}

	// invalid nonce
	signature, data := makeTestRequest(user, node, ephmr, nil, 1024, grace)
	res, err := Guard(bs, signer, identity, signature, data)
	assert.Nil(res)
	assert.Nil(err)
	key := crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey := append(key, "EPHEMERAL"...)
	available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	assert.Equal(EphemeralLimitQuota-1, available)
	assert.Nil(err)

	// invalid encryption
	signature, data = makeTestRequest(user, crypto.PublicKey(user), ephmr, nil, 1034, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	assert.Nil(res)
	assert.Contains(err.Error(), "invalid data ")
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	assert.Equal(EphemeralLimitQuota-1, available)
	assert.Nil(err)

	// invalid ephemeral
	signature, data = makeTestRequest(user, node, crypto.PublicKeyBytes(node), nil, 1034, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	assert.Nil(res)
	assert.Nil(err)
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	assert.Equal(EphemeralLimitQuota-2, available)
	assert.Nil(err)

	// invalid signature
	for i := 1; i < 6; i++ {
		signature, data = makeTestRequest(user, node, ephmr, nil, uint64(1033+i), grace)
		res, err := Guard(bs, signer, identity, hex.EncodeToString(ephmr), data)
		assert.Nil(res)
		assert.Nil(err)
		key = crypto.PublicKeyBytes(crypto.PublicKey(user))
		lkey = append(key, "EPHEMERAL"...)
		available, err := bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
		assert.Equal(EphemeralLimitQuota-2, available)
		assert.Nil(err)
		lkey = append(key, "SECRET"...)
		available, err = bs.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
		assert.Equal(SecretLimitQuota-i, available)
		assert.Nil(err)
	}

	signature, data = makeTestRequest(user, node, ephmr, nil, 1039, grace)
	res, err = Guard(bs, signer, identity, signature, data)
	assert.Equal(SecretLimitQuota-5, res.Available)
	assert.Equal(uint64(1039), res.Nonce)
	assert.Nil(err)
	key = crypto.PublicKeyBytes(crypto.PublicKey(user))
	lkey = append(key, "EPHEMERAL"...)
	available, err = bs.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	assert.Equal(EphemeralLimitQuota-2, available)
	assert.Nil(err)
	lkey = append(key, "SECRET"...)
	available, err = bs.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
	assert.Equal(SecretLimitQuota-5, available)
	assert.Nil(err)
}

func TestAssigneeAndRotation(t *testing.T) {
	assert := assert.New(t)

	dir, _ := os.MkdirTemp("/tmp", "tip-keeper-test")
	conf := &store.BadgerConfiguration{Dir: dir}
	bs, _ := store.OpenBadger(context.Background(), conf)
	defer bs.Close()

	suite := en256.NewSuiteBn256()
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
	assert.Nil(err)
	assert.Equal(SecretLimitQuota, res.Available)
	assert.Equal(1024, int(res.Nonce))

	ephmr = crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace = uint64(time.Hour * 24 * 128)
	signature, data = makeTestRequest(u2, node, ephmr, nil, 1024, grace)
	res, err = Guard(bs, signer, i2, signature, data)
	assert.Nil(err)
	assert.Equal(SecretLimitQuota, res.Available)
	assert.Equal(1024, int(res.Nonce))

	ephmr = crypto.PrivateKeyBytes(suite.Scalar().Pick(random.New()))
	grace = uint64(time.Hour * 24 * 128)
	signature, data = makeTestRequest(u3, node, ephmr, nil, 1024, grace)
	res, err = Guard(bs, signer, i3, signature, data)
	assert.Nil(err)
	assert.Equal(SecretLimitQuota, res.Available)
	assert.Equal(1024, int(res.Nonce))
}

func makeTestRequest(user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64) (string, string) {
	return makeTestRequestWithAssigneeAndRotation(user, signer, ephmr, rtt, nonce, grace, "", "")
}

func makeTestRequestWithAssigneeAndRotation(user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64, assignee, rotation string) (string, string) {
	pkey := crypto.PublicKey(user)
	msg := crypto.PublicKeyBytes(pkey)
	msg = append(msg, ephmr...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	data := map[string]interface{}{
		"identity":  crypto.PublicKeyString(pkey),
		"ephemeral": hex.EncodeToString(ephmr),
		"nonce":     nonce,
		"grace":     grace,
	}
	if rtt != nil {
		msg = append(msg, rtt[:]...)
		data["rotate"] = hex.EncodeToString(rtt)
	}
	b, _ := json.Marshal(data)
	cipher := crypto.Encrypt(signer, user, b)
	sig, _ := crypto.Sign(user, msg)
	return hex.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(cipher[:])
}
