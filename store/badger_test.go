package store

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/assert"
)

func TestBadgerLimit(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	key := []byte("limit-check-test")
	available, err := bs.CheckLimit(key, time.Second*3, 3, true)
	assert.Nil(err)
	assert.Equal(3, available)
	available, err = bs.CheckLimit(key, time.Second*3, 3, true)
	assert.Nil(err)
	assert.Equal(2, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(3, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(2, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(1, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(0, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(0, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	assert.Nil(err)
	assert.Equal(0, available)
}

func TestBadgerNonce(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	key := []byte("nonce-check-test-key")
	nonce := []byte("nonce-check-test-value")
	res, err := bs.CheckEphemeralNonce(key, nonce, 0, time.Second)
	assert.Nil(err)
	assert.True(res)
	res, err = bs.CheckEphemeralNonce(key, nonce, 0, time.Second)
	assert.Nil(err)
	assert.False(res)
	res, err = bs.CheckEphemeralNonce(key, nonce, 1, time.Second)
	assert.Nil(err)
	assert.True(res)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 2, time.Second)
	assert.Nil(err)
	assert.False(res)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 3, time.Second)
	assert.Nil(err)
	assert.False(res)
	time.Sleep(time.Second)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 0, time.Second)
	assert.Nil(err)
	assert.True(res)
}

func TestBadgerPolyGroup(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	valid, err := bs.CheckPolyGroup([]byte("group"))
	assert.Nil(err)
	assert.True(valid)

	valid, err = bs.CheckPolyGroup([]byte("group"))
	assert.Nil(err)
	assert.True(valid)

	valid, err = bs.CheckPolyGroup([]byte("invalid"))
	assert.Nil(err)
	assert.False(valid)

	valid, err = bs.CheckPolyGroup([]byte("group"))
	assert.Nil(err)
	assert.True(valid)
}

func TestBadgerAssignee(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	a, b, c := []byte{1}, []byte{2}, []byte{3}
	err := bs.WriteAssignee(a, b)
	assert.Nil(err)
	available, err := bs.CheckLimit(a, time.Second*3, 3, true)
	assert.Nil(err)
	assert.Equal(3, available)
	err = bs.WriteAssignee(a, b)
	assert.Contains(err.Error(), "invalid assignor as is assignee")
	res, err := bs.CheckEphemeralNonce(a, a, 0, time.Second)
	assert.Nil(err)
	assert.True(res)
	err = bs.WriteAssignee(a, b)
	assert.Contains(err.Error(), "invalid assignor as is assignee")
	ee, err := bs.ReadAssignee(a)
	assert.Nil(err)
	assert.Equal(b, ee)
	or, err := bs.ReadAssignor(a)
	assert.Nil(err)
	assert.Nil(or)
	or, err = bs.ReadAssignor(b)
	assert.Nil(err)
	assert.Equal(a, or)
	res, err = bs.CheckEphemeralNonce(a, a, 0, time.Second)
	assert.Nil(err)
	assert.False(res)
	res, err = bs.CheckEphemeralNonce(b, a, 0, time.Second)
	assert.Nil(err)
	assert.True(res)
	res, err = bs.CheckEphemeralNonce(b, b, 1, time.Second)
	assert.Nil(err)
	assert.False(res)
	res, err = bs.CheckEphemeralNonce(b, a, 1, time.Second)
	assert.Nil(err)
	assert.True(res)
	res, err = bs.CheckEphemeralNonce(c, c, 0, time.Second)
	assert.Nil(err)
	assert.True(res)
	err = bs.WriteAssignee(a, c)
	assert.Nil(err)
	ee, err = bs.ReadAssignee(a)
	assert.Nil(err)
	assert.Equal(c, ee)
	or, err = bs.ReadAssignor(a)
	assert.Nil(err)
	assert.Nil(or)
	or, err = bs.ReadAssignor(b)
	assert.Nil(err)
	assert.Nil(or)
	or, err = bs.ReadAssignor(c)
	assert.Nil(err)
	assert.Equal(or, a)
	res, err = bs.CheckEphemeralNonce(c, a, 1, time.Second)
	assert.Nil(err)
	assert.False(res)
	res, err = bs.CheckEphemeralNonce(c, c, 1, time.Second)
	assert.Nil(err)
	assert.True(res)
	res, err = bs.CheckEphemeralNonce(b, a, 2, time.Second)
	assert.Nil(err)
	assert.True(res)
	err = bs.WriteAssignee(a, a)
	assert.Nil(err)
	ee, err = bs.ReadAssignee(a)
	assert.Nil(err)
	assert.Equal(a, ee)
	or, err = bs.ReadAssignor(a)
	assert.Nil(err)
	assert.Equal(a, or)
	or, err = bs.ReadAssignor(b)
	assert.Nil(err)
	assert.Nil(or)
	or, err = bs.ReadAssignor(c)
	assert.Nil(err)
	assert.Nil(or)
}

func TestBadgerWatch(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	suite := bn256.NewSuiteBn256()
	user := suite.Scalar().Pick(random.New())
	identity := crypto.PublicKeyBytes(crypto.PublicKey(user))
	watcher := make([]byte, 32)
	rand.Read(watcher)
	genesis, counter, err := bs.WriteSignRequest(identity, watcher)
	assert.Nil(err)
	assert.Equal(1, counter)
	assert.True(genesis.Add(time.Minute).After(time.Now()))
	genesisExist, counterExist, err := bs.Watch(watcher)
	assert.Nil(err)
	assert.Equal(counter, counterExist)
	assert.True(genesis.Equal(genesisExist))
	genesis, counter, err = bs.WriteSignRequest(identity, watcher)
	assert.Nil(err)
	assert.Equal(1, counter)
	assert.True(genesis.Add(time.Minute).After(time.Now()))
	genesisExist, counterExist, err = bs.Watch(watcher)
	assert.Nil(err)
	assert.Equal(counter, counterExist)
	assert.True(genesis.Equal(genesisExist))
	err = bs.WriteAssignee(identity, identity)
	assert.Nil(err)
	genesisExist, counterExist, err = bs.Watch(watcher)
	assert.Nil(err)
	assert.Equal(2, counterExist)
	assert.True(genesis.Equal(genesisExist))
}

func testBadgerStore() *BadgerStorage {
	dir, err := os.MkdirTemp("/tmp", "tip-badger-test")
	if err != nil {
		panic(err)
	}
	conf := &BadgerConfiguration{
		Dir: dir,
	}
	bs, err := OpenBadger(context.Background(), conf)
	if err != nil {
		panic(err)
	}
	return bs
}
