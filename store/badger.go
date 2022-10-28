package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v3"
)

const (
	badgerKeyPolyGroup  = "POLY#GROUP"
	badgerKeyPolyPublic = "POLY#PUBLIC"
	badgerKeyPolyShare  = "POLY#SHARE"

	badgerKeyPrefixAssignee = "ASSIGNEE#"
	badgerKeyPrefixAssignor = "ASSIGNOR#"
	badgerKeyPrefixWatcher  = "WATCHER#"
	badgerKeyPrefixLimit    = "LIMIT#"
	badgerKeyPrefixNonce    = "NONCE#"
	badgerKeyPrefixGenesis  = "GENESIS#"
	badgerKeyPrefixCounter  = "COUNTER#"
	maxUint64               = ^uint64(0)
)

type BadgerConfiguration struct {
	Dir string `toml:"dir"`
}

type BadgerStorage struct {
	db *badger.DB
}

func (bs *BadgerStorage) CheckLimit(key []byte, window time.Duration, quota uint32, increase bool) (int, error) {
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
		if available == 0 || !increase {
			return nil
		}

		available--
		buf := uint64ToBytes(now)
		entry := badger.NewEntry(append(prefix, buf...), []byte{1})
		entry = entry.WithTTL(window * 2)
		return txn.SetEntry(entry)
	})
	return int(available), err
}

func (bs *BadgerStorage) CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error) {
	var valid bool
	now := time.Now().UnixNano()
	val := uint64ToBytes(uint64(now))
	val = append(val, ephemeral...)
	buf := uint64ToBytes(nonce)
	val = append(val, buf...)
	key = append([]byte(badgerKeyPrefixNonce), key...)
	err := bs.db.Update(func(txn *badger.Txn) error {
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

func (bs *BadgerStorage) RotateEphemeralNonce(key, ephemeral []byte, nonce uint64) error {
	now := time.Now().UnixNano()
	key = append([]byte(badgerKeyPrefixNonce), key...)

	val := uint64ToBytes(uint64(now))
	val = append(val, ephemeral...)

	buf := uint64ToBytes(nonce)
	val = append(val, buf...)

	return bs.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, val)
	})
}

func (bs *BadgerStorage) CheckPolyGroup(group []byte) (bool, error) {
	var valid bool
	key := []byte(badgerKeyPolyGroup)
	err := bs.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			valid = true
			return txn.Set(key, group)
		} else if err != nil {
			return err
		}
		old, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		if bytes.Compare(old, group) == 0 {
			valid = true
		}
		return nil
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

func (bs *BadgerStorage) WriteAssignee(key []byte, assignee []byte) error {
	return bs.db.Update(func(txn *badger.Txn) error {
		if oa, err := readKey(txn, badgerKeyPrefixAssignee, key); err != nil {
			return err
		} else if oa != nil {
			rk := append([]byte(badgerKeyPrefixAssignor), oa...)
			err = txn.Delete(rk)
			if err != nil {
				return err
			}
		}

		if bytes.Compare(key, assignee) != 0 {
			old, err := readKey(txn, badgerKeyPrefixAssignee, assignee)
			if err != nil {
				return err
			} else if old != nil {
				return fmt.Errorf("invalid assignee as is assignee")
			}
			old, err = readKey(txn, badgerKeyPrefixAssignor, assignee)
			if err != nil {
				return err
			} else if old != nil {
				return fmt.Errorf("invalid assignor as is assignee")
			}
		}

		lk := append([]byte(badgerKeyPrefixAssignee), key...)
		err := txn.Set(lk, assignee)
		if err != nil {
			return err
		}
		rk := append([]byte(badgerKeyPrefixAssignor), assignee...)
		err = txn.Set(rk, key)
		if err != nil {
			return err
		}

		var counter uint64
		cb, err := readKey(txn, badgerKeyPrefixCounter, key)
		if err != nil {
			return err
		} else if cb != nil {
			counter = binary.BigEndian.Uint64(cb)
		}
		ck := append([]byte(badgerKeyPrefixCounter), key...)
		cv := uint64ToBytes(counter + 1)
		return txn.Set(ck, cv)
	})
}

func (bs *BadgerStorage) ReadAssignee(key []byte) ([]byte, error) {
	txn := bs.db.NewTransaction(false)
	defer txn.Discard()

	return readKey(txn, badgerKeyPrefixAssignee, key)
}

func (bs *BadgerStorage) ReadAssignor(key []byte) ([]byte, error) {
	txn := bs.db.NewTransaction(false)
	defer txn.Discard()

	return readKey(txn, badgerKeyPrefixAssignor, key)
}

func (bs *BadgerStorage) Watch(key []byte) ([]byte, time.Time, int, error) {
	txn := bs.db.NewTransaction(false)
	defer txn.Discard()

	assignor, err := readKey(txn, badgerKeyPrefixWatcher, key)
	if err != nil {
		return nil, time.Time{}, 0, err
	} else if assignor == nil {
		return nil, time.Time{}, 0, nil
	}

	gb, err := readKey(txn, badgerKeyPrefixGenesis, assignor)
	if err != nil {
		return assignor, time.Time{}, 0, err
	}
	genesis := time.Unix(0, int64(binary.BigEndian.Uint64(gb)))

	cb, err := readKey(txn, badgerKeyPrefixCounter, assignor)
	if err != nil {
		return assignor, time.Time{}, 0, err
	}
	counter := int(binary.BigEndian.Uint64(cb))

	return assignor, genesis, counter, nil
}

func (bs *BadgerStorage) WriteSignRequest(assignor, watcher []byte) (time.Time, int, error) {
	if len(assignor) == 0 || len(watcher) == 0 {
		return time.Time{}, 0, fmt.Errorf("invalid assignor %x or watcher %x", assignor, watcher)
	}
	var counter int
	var genesis time.Time
	err := bs.db.Update(func(txn *badger.Txn) error {
		cb, err := readKey(txn, badgerKeyPrefixCounter, assignor)
		if err != nil {
			return err
		} else if cb != nil {
			counter = int(binary.BigEndian.Uint64(cb))
		} else {
			counter = 1
		}

		old, err := readKey(txn, badgerKeyPrefixGenesis, assignor)
		if err != nil {
			return err
		} else if old != nil {
			genesis = time.Unix(0, int64(binary.BigEndian.Uint64(old)))
		} else {
			genesis = time.Now()
		}

		key := append([]byte(badgerKeyPrefixGenesis), assignor...)
		val := uint64ToBytes(uint64(genesis.UnixNano()))
		err = txn.Set(key, val)
		if err != nil {
			return err
		}

		key = append([]byte(badgerKeyPrefixCounter), assignor...)
		val = uint64ToBytes(uint64(counter))
		err = txn.Set(key, val)
		if err != nil {
			return err
		}

		old, err = readKey(txn, badgerKeyPrefixWatcher, watcher)
		if err != nil {
			return err
		} else if old != nil && bytes.Compare(old, assignor) != 0 {
			return fmt.Errorf("invalid watcher %x", watcher)
		}
		key = append([]byte(badgerKeyPrefixWatcher), watcher...)
		return txn.Set(key, assignor)
	})
	return genesis, counter, err
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

func readKey(txn *badger.Txn, prefix string, key []byte) ([]byte, error) {
	key = append([]byte(prefix), key...)
	item, err := txn.Get(key)
	if err == badger.ErrKeyNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return item.ValueCopy(nil)
}

func uint64ToBytes(i uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, i)
	return buf
}
