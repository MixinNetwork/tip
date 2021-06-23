package store

import (
	"context"
	"os"
	"testing"
	"time"

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

func TestBadgerGroupIdentity(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	valid, err := bs.CheckGroupIdenity([]byte("group"))
	assert.Nil(err)
	assert.True(valid)

	valid, err = bs.CheckGroupIdenity([]byte("group"))
	assert.Nil(err)
	assert.True(valid)

	valid, err = bs.CheckGroupIdenity([]byte("invalid"))
	assert.Nil(err)
	assert.False(valid)

	valid, err = bs.CheckGroupIdenity([]byte("group"))
	assert.Nil(err)
	assert.True(valid)
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
