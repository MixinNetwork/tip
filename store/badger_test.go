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
	"github.com/stretchr/testify/require"
)

func TestBadgerLimit(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	key := []byte("limit-check-test")
	available, err := bs.CheckLimit(key, time.Second*3, 3, true)
	require.Nil(err)
	require.Equal(2, available)
	available, err = bs.CheckLimit(key, time.Second*3, 3, true)
	require.Nil(err)
	require.Equal(1, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(2, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(1, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(0, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(0, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(0, available)
	available, err = bs.CheckLimit(key, time.Second*3, 5, true)
	require.Nil(err)
	require.Equal(0, available)
}

func TestBadgerNonce(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	key := []byte("nonce-check-test-key")
	nonce := []byte("nonce-check-test-value")
	res, err := bs.CheckEphemeralNonce(key, nonce, 0, time.Second)
	require.Nil(err)
	require.True(res)
	res, err = bs.CheckEphemeralNonce(key, nonce, 0, time.Second)
	require.Nil(err)
	require.False(res)
	res, err = bs.CheckEphemeralNonce(key, nonce, 1, time.Second)
	require.Nil(err)
	require.True(res)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 2, time.Second)
	require.Nil(err)
	require.False(res)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 3, time.Second)
	require.Nil(err)
	require.False(res)
	time.Sleep(time.Second)
	res, err = bs.CheckEphemeralNonce(key, append(nonce, 1), 0, time.Second)
	require.Nil(err)
	require.True(res)
}

func TestBadgerPolyGroup(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	valid, err := bs.CheckPolyGroup([]byte("group"))
	require.Nil(err)
	require.True(valid)

	valid, err = bs.CheckPolyGroup([]byte("group"))
	require.Nil(err)
	require.True(valid)

	valid, err = bs.CheckPolyGroup([]byte("invalid"))
	require.Nil(err)
	require.False(valid)

	valid, err = bs.CheckPolyGroup([]byte("group"))
	require.Nil(err)
	require.True(valid)
}

func TestBadgerAssignee(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	a, b, c := []byte{1}, []byte{2}, []byte{3}
	err := bs.WriteAssignee(a, b)
	require.Nil(err)
	available, err := bs.CheckLimit(a, time.Second*3, 3, true)
	require.Nil(err)
	require.Equal(2, available)
	err = bs.WriteAssignee(a, b)
	require.Nil(err)
	res, err := bs.CheckEphemeralNonce(a, a, 0, time.Second)
	require.Nil(err)
	require.True(res)
	err = bs.WriteAssignee(a, b)
	require.Nil(err)
	ee, err := bs.ReadAssignee(a)
	require.Nil(err)
	require.Equal(b, ee)
	or, err := bs.ReadAssignor(a)
	require.Nil(err)
	require.Nil(or)
	or, err = bs.ReadAssignor(b)
	require.Nil(err)
	require.Equal(a, or)
	res, err = bs.CheckEphemeralNonce(a, a, 0, time.Second)
	require.Nil(err)
	require.False(res)
	res, err = bs.CheckEphemeralNonce(b, a, 0, time.Second)
	require.Nil(err)
	require.True(res)
	res, err = bs.CheckEphemeralNonce(b, b, 1, time.Second)
	require.Nil(err)
	require.False(res)
	res, err = bs.CheckEphemeralNonce(b, a, 1, time.Second)
	require.Nil(err)
	require.True(res)
	res, err = bs.CheckEphemeralNonce(c, c, 0, time.Second)
	require.Nil(err)
	require.True(res)
	err = bs.WriteAssignee(a, c)
	require.Nil(err)
	ee, err = bs.ReadAssignee(a)
	require.Nil(err)
	require.Equal(c, ee)
	or, err = bs.ReadAssignor(a)
	require.Nil(err)
	require.Nil(or)
	or, err = bs.ReadAssignor(b)
	require.Nil(err)
	require.Nil(or)
	or, err = bs.ReadAssignor(c)
	require.Nil(err)
	require.Equal(or, a)
	res, err = bs.CheckEphemeralNonce(c, a, 1, time.Second)
	require.Nil(err)
	require.False(res)
	res, err = bs.CheckEphemeralNonce(c, c, 1, time.Second)
	require.Nil(err)
	require.True(res)
	res, err = bs.CheckEphemeralNonce(b, a, 2, time.Second)
	require.Nil(err)
	require.True(res)
	err = bs.WriteAssignee(a, a)
	require.Nil(err)
	ee, err = bs.ReadAssignee(a)
	require.Nil(err)
	require.Equal(a, ee)
	or, err = bs.ReadAssignor(a)
	require.Nil(err)
	require.Equal(a, or)
	or, err = bs.ReadAssignor(b)
	require.Nil(err)
	require.Nil(or)
	or, err = bs.ReadAssignor(c)
	require.Nil(err)
	require.Nil(or)
}

func TestBadgerWatch(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	suite := bn256.NewSuiteBn256()
	user := suite.Scalar().Pick(random.New())
	identity := crypto.PublicKeyBytes(crypto.PublicKey(user))
	watcher := make([]byte, 32)
	rand.Read(watcher)
	genesis, counter, err := bs.WriteSignRequest(identity, watcher)
	require.Nil(err)
	require.Equal(1, counter)
	require.True(genesis.Add(time.Minute).After(time.Now()))
	oas, genesisExist, counterExist, err := bs.Watch(watcher)
	require.Nil(err)
	require.Equal(counter, counterExist)
	require.True(genesis.Equal(genesisExist))
	require.Equal(identity, oas)
	genesis, counter, err = bs.WriteSignRequest(identity, watcher)
	require.Nil(err)
	require.Equal(1, counter)
	require.True(genesis.Add(time.Minute).After(time.Now()))
	oas, genesisExist, counterExist, err = bs.Watch(watcher)
	require.Nil(err)
	require.Equal(counter, counterExist)
	require.True(genesis.Equal(genesisExist))
	require.Equal(identity, oas)
	err = bs.WriteAssignee(identity, identity)
	require.Nil(err)
	oas, genesisExist, counterExist, err = bs.Watch(watcher)
	require.Nil(err)
	require.Equal(2, counterExist)
	require.True(genesis.Equal(genesisExist))
	require.Equal(identity, oas)
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
