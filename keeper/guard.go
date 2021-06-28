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
	EphemeralLimitWindow = time.Hour * 24
	EphemeralLimitQuota  = 42
	SecretLimitWindow    = time.Hour * 24 * 7
	SecretLimitQuota     = 7
)

type Response struct {
	Available int
	Nonce     uint64
	Identity  kyber.Point
}

func Guard(store store.Storage, priv kyber.Scalar, identity, signature, data string) (*Response, error) {
	b, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil || len(b) < aes.BlockSize*2 || len(b)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid data %s", data)
	}
	pub, err := crypto.PubKeyFromBase58(identity)
	if err != nil {
		return nil, fmt.Errorf("invalid idenity %s", identity)
	}
	b = crypto.Decrypt(pub, priv, b)

	var body body
	err = json.Unmarshal(b, &body)
	if err != nil {
		return nil, fmt.Errorf("invalid data %s", string(b))
	}
	if body.Identity != identity {
		return nil, fmt.Errorf("invalid idenity %s", identity)
	}
	var ab []byte
	if len(body.Assignee) > 0 {
		ab, err = checkAssignee(body.Assignee)
		if err != nil {
			return nil, err
		}
	}
	eb, valid := new(big.Int).SetString(body.Ephemeral, 16)
	if !valid {
		return nil, fmt.Errorf("invalid ephemeral %s", body.Ephemeral)
	}
	rb, _ := new(big.Int).SetString(body.Rotate, 16)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature %s", signature)
	}
	key := crypto.PublicKeyBytes(pub)

	lkey := append(key, "EPHEMERAL"...)
	available, err := store.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	if err != nil || available < 1 {
		return nil, err
	}
	nonce, grace := uint64(body.Nonce), time.Duration(body.Grace)
	if grace < EphemeralGracePeriod {
		grace = EphemeralGracePeriod
	}
	valid, err = store.CheckEphemeralNonce(key, eb.Bytes(), nonce, grace)
	if err != nil {
		return nil, err
	}
	if !valid {
		_, err = store.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, true)
		return nil, err
	}
	if rb != nil && rb.Sign() > 0 {
		err = store.RotateEphemeralNonce(key, rb.Bytes(), nonce)
		if err != nil {
			return nil, err
		}
	}

	lkey = append(key, "SECRET"...)
	available, err = store.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
	if err != nil || available < 1 {
		return nil, err
	}
	err = checkSignature(pub, sig, eb, rb, nonce, uint64(grace), ab)
	if err == nil {
		if len(ab) > 0 {
			err := store.WriteAssignee(ab[:128], crypto.PublicKeyBytes(pub))
			if err != nil {
				return nil, err
			}
		}
		ib, err := store.ReadAssignee(crypto.PublicKeyBytes(pub))
		if err != nil {
			return nil, err
		}
		if len(ib) > 0 {
			pub, err = crypto.PubKeyFromBytes(ib)
			if err != nil {
				panic(err)
			}
		}
		return &Response{
			Available: available,
			Nonce:     nonce,
			Identity:  pub,
		}, nil
	}
	_, err = store.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, true)
	return nil, err
}

func checkSignature(pub kyber.Point, sig []byte, eb, rb *big.Int, nonce, grace uint64, ab []byte) error {
	msg := crypto.PublicKeyBytes(pub)
	msg = append(msg, eb.Bytes()...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	if rb != nil && rb.Sign() > 0 {
		msg = append(msg, rb.Bytes()...)
	}
	msg = append(msg, ab...)
	return crypto.Verify(pub, msg, sig)
}

func checkAssignee(as string) ([]byte, error) {
	ab, err := hex.DecodeString(as)
	if err != nil {
		return nil, fmt.Errorf("invalid assignee format %s", err)
	}
	if len(ab) != 192 {
		return nil, fmt.Errorf("invalid assignee format %d", len(as))
	}
	pub, err := crypto.PubKeyFromBytes(ab[:128])
	if err != nil {
		return nil, fmt.Errorf("invalid assignee public key %d", err)
	}
	return ab, crypto.Verify(pub, ab[:128], ab[128:])
}

type body struct {
	// main identity public key to check signature
	Identity string `json:"identity"`

	// a new identity to represent the main identity
	Assignee string `json:"assignee"`

	// the ephemeral secret to authenticate
	Ephemeral string `json:"ephemeral"`

	// ephemeral grace period to maintain the secret valid, the grace
	// will be extended for each valid request, and if the grace expired
	// the ephemeral can be reset
	Grace int64 `json:"grace"`

	// ensure each request can only be used once
	Nonce int64 `json:"nonce"`

	// the ephemeral rotation allows user to use a new secret
	// e.g. when they cooperate with others to generate a non-random
	// ephemeral to replace their on-device random one
	Rotate string `json:"rotate"`
}
