package keeper

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
)

const (
	NonceGracePeriod = time.Hour * 24 * 128
	LimitWindow      = time.Hour * 24 * 7
	LimitQuota       = 5
)

func Check(store store.Storage, identity, ephemeral, signature string, nonce int64) (int, error) {
	pub, err := signer.PubKeyFromBase58(identity)
	if err != nil {
		return 0, fmt.Errorf("invalid idenity %s", identity)
	}
	nb, valid := new(big.Int).SetString(ephemeral, 16)
	if !valid {
		return 0, fmt.Errorf("invalid ephemeral %s", ephemeral)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return 0, fmt.Errorf("invalid signature %s", signature)
	}
	key, err := pub.MarshalBinary()
	if err != nil {
		panic(err)
	}

	valid, err = store.CheckNonce(key, nb.Bytes(), uint64(nonce), NonceGracePeriod)
	if err != nil {
		return 0, err
	} else if !valid {
		return 0, nil
	}

	available, err := store.CheckLimit(key, LimitWindow, LimitQuota, false)
	if err != nil {
		return 0, err
	} else if available < 1 {
		return 0, nil
	}

	msg := append(key, nb.Bytes()...)
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	err = scheme.Verify(pub, msg, sig)
	if err == nil {
		return available, nil
	}

	return store.CheckLimit(key, LimitWindow, LimitQuota, true)
}
