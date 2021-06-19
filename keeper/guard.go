package keeper

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
)

const (
	EphemeralGracePeriod = time.Hour * 24 * 128
	LimitWindow          = time.Hour * 24 * 7
	LimitQuota           = 7
)

func Guard(store store.Storage, priv kyber.Scalar, identity, signature, data string) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil || len(b) < aes.BlockSize*2 {
		return 0, fmt.Errorf("invalid data %s", data)
	}
	pub, err := crypto.PubKeyFromBase58(identity)
	if err != nil {
		return 0, fmt.Errorf("invalid idenity %s", identity)
	}
	b = crypto.Decrypt(pub, priv, b)

	var body body
	err = json.Unmarshal(b, &body)
	if err != nil {
		return 0, fmt.Errorf("invalid data %s", string(b))
	}
	if body.Identity != identity {
		return 0, fmt.Errorf("invalid idenity %s", identity)
	}
	eb, valid := new(big.Int).SetString(body.Ephemeral, 16)
	if !valid {
		return 0, fmt.Errorf("invalid ephemeral %s", body.Ephemeral)
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return 0, fmt.Errorf("invalid signature %s", signature)
	}
	key := crypto.PublicKeyBytes(pub)

	nonce, grace := uint64(body.Nonce), time.Duration(body.Grace)
	if grace < EphemeralGracePeriod {
		grace = EphemeralGracePeriod
	}
	valid, err = store.CheckEphemeralNonce(key, eb.Bytes(), nonce, grace)
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

	err = checkSignature(pub, sig, eb, nonce, uint64(grace))
	if err == nil {
		return available, nil
	}

	_, err = store.CheckLimit(key, LimitWindow, LimitQuota, true)
	return 0, err
}

func checkSignature(pub kyber.Point, sig []byte, eb *big.Int, nonce, grace uint64) error {
	msg := crypto.PublicKeyBytes(pub)
	msg = append(msg, eb.Bytes()...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	return crypto.Verify(pub, msg, sig)
}

type body struct {
	Identity  string `json:"identity"`
	Ephemeral string `json:"ephemeral"`
	Grace     int64  `json:"grace"`
	Nonce     int64  `json:"nonce"`
}
