package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"time"

	"github.com/dgraph-io/badger/v3"
)

const (
	badgerKeyPolyPublic = "POLY#PUBLIC"
	badgerKeyPolyShare  = "POLY#SHARE"

	badgerKeyPrefixLimit = "LIMIT#"
	badgerKeyPrefixNonce = "NONCE#"
	maxUint64            = ^uint64(0)
)

type BadgerConfiguration struct {
	Dir string `toml:"dir"`
}

type BadgerStorage struct {
	db *badger.DB
}

func (bs *BadgerStorage) CheckLimit(key []byte, window time.Duration, quota uint32, count bool) (int, error) {
	now := uint64(time.Now().UnixNano())
	if now >= maxUint64/2 || now <= uint64(window) {
		panic(time.Now())
	}
	now = maxUint64 - now
	threshold := now + uint64(window)
	available := quota

	prefix := append([]byte(badgerKeyPrefixLimit), key...)
	err := bs.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); available > 0 && it.ValidForPrefix(prefix); it.Next() {
			ts := it.Item().Key()[len(prefix):]
			if binary.BigEndian.Uint64(ts) > threshold {
				break
			}
			available--
		}
		if available == 0 || !count {
			return nil
		}

		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], now)
		return txn.Set(append(prefix, buf[:]...), []byte{1})
	})
	return int(available), err
}

func (bs *BadgerStorage) CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error) {
	var valid bool
	buf, now := make([]byte, 8), time.Now().UnixNano()
	binary.BigEndian.PutUint64(buf, uint64(now))
	val := append(buf, ephemeral...)
	binary.BigEndian.PutUint64(buf, nonce)
	val = append(val, buf...)
	err := bs.db.Update(func(txn *badger.Txn) error {
		key = append([]byte(badgerKeyPrefixNonce), key...)
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			valid = true
			return txn.Set(key, val)
		} else if err != nil {
			return err
		}
		v, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		old := binary.BigEndian.Uint64(v[:8])
		if old+uint64(grace) < uint64(now) {
			valid = true
			return txn.Set(key, val)
		}
		if bytes.Compare(v[8:len(v)-8], ephemeral) != 0 {
			return nil
		}
		old = binary.BigEndian.Uint64(v[len(v)-8:])
		if old >= nonce {
			return nil
		}
		valid = true
		return txn.Set(key, val)
	})
	return valid, err
}

func (bs *BadgerStorage) ReadPolyShare() ([]byte, error) {
	txn := bs.db.NewTransaction(false)
	defer txn.Discard()

	item, err := txn.Get([]byte(badgerKeyPolyShare))
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item.ValueCopy(nil)
}

func (bs *BadgerStorage) ReadPolyPublic() ([]byte, error) {
	txn := bs.db.NewTransaction(false)
	defer txn.Discard()

	item, err := txn.Get([]byte(badgerKeyPolyPublic))
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item.ValueCopy(nil)
}

func (bs *BadgerStorage) WritePoly(public, share []byte) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(badgerKeyPolyPublic), public)
		if err != nil {
			return err
		}
		return txn.Set([]byte(badgerKeyPolyShare), share)
	})
}

func OpenBadger(ctx context.Context, conf *BadgerConfiguration) (*BadgerStorage, error) {
	db, err := badger.Open(badger.DefaultOptions(conf.Dir))
	if err != nil {
		return nil, err
	}
	return &BadgerStorage{
		db: db,
	}, nil
}

func (bs *BadgerStorage) Close() {
	bs.db.Close()
}
