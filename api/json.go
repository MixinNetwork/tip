package api

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/keeper"
	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/tbls"
)

type SignRequest struct {
	Action    string `json:"action"`
	Watcher   string `json:"watcher"`
	Identity  string `json:"identity"`
	Signature string `json:"signature"`
	Data      string `json:"data"`
}

func info(key kyber.Scalar, sigrs []dkg.Node, poly []kyber.Point) (interface{}, string) {
	signers := make([]map[string]interface{}, len(sigrs))
	for i, s := range sigrs {
		signers[i] = map[string]interface{}{
			"index":    s.Index,
			"identity": crypto.PublicKeyString(s.Public),
		}
	}
	commitments := make([]string, len(poly))
	for i, c := range poly {
		commitments[i] = crypto.PublicKeyString(c)
	}
	id := crypto.PublicKey(key)
	data := map[string]interface{}{
		"identity":    crypto.PublicKeyString(id),
		"signers":     signers,
		"commitments": commitments,
	}
	b, _ := json.Marshal(data)
	sig, _ := crypto.Sign(key, b)
	return data, hex.EncodeToString(sig)
}

func watch(store store.Storage, watcher string) (time.Time, int, error) {
	key, _ := hex.DecodeString(watcher)
	if len(key) != 32 {
		return time.Time{}, 0, fmt.Errorf("invalid watcher %s", watcher)
	}

	_, genesis, counter, err := store.Watch(key)
	return genesis, counter, err
}

func sign(key kyber.Scalar, store store.Storage, body *SignRequest, priv *share.PriShare) (interface{}, string, error) {
	res, err := keeper.Guard(store, key, body.Identity, body.Signature, body.Data)
	if err != nil {
		logger.Debug("keeper.Guard", body.Identity, body.Watcher, body.Signature, err)
		return nil, "", ErrUnknown
	}
	if res.Available < 1 {
		logger.Debug("keeper.Available", body.Identity, body.Watcher, body.Signature)
		return nil, "", ErrTooManyRequest
	}
	watcher, _ := hex.DecodeString(body.Watcher)
	if bytes.Compare(res.Watcher, watcher) != 0 {
		logger.Debug("keeper.Watch", body.Identity, body.Watcher, body.Signature, body.Watcher)
		return nil, "", ErrInvalidAssignor
	}

	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	partial, err := scheme.Sign(priv, res.Assignor)
	if err != nil {
		panic(err)
	}

	genesis, counter, err := store.WriteSignRequest(res.Assignor, res.Watcher)
	if err != nil {
		logger.Debug("store.WriteSignRequest", err)
		return nil, "", ErrUnknown
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, res.Nonce)
	plain := append(buf, partial...)
	plain = append(plain, res.Assignor...)
	binary.BigEndian.PutUint64(buf, uint64(genesis.UnixNano()))
	plain = append(plain, buf...)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	plain = append(plain, buf...)
	cipher := crypto.Encrypt(res.Identity, key, plain)
	data := map[string]interface{}{
		"cipher": hex.EncodeToString(cipher),
	}
	b, _ := json.Marshal(data)
	sig, _ := crypto.Sign(key, b)
	return data, hex.EncodeToString(sig), nil
}
