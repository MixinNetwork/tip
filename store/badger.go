package store

import (
	"context"

	"github.com/dgraph-io/badger/v3"
)

const (
	badgerKeyPolyPublic = "POLY#PUBLIC"
	badgerKeyPolyShare  = "POLY#SHARE"
)

type BadgerConfiguration struct {
	Dir string `toml:"dir"`
}

type BadgerStorage struct {
	db *badger.DB
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
