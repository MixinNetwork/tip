package api

import (
	"encoding/hex"
	"encoding/json"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/keeper"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
)

type SignRequest struct {
	Data      string `json:"data"`
	Identity  string `json:"identity"`
	Signature string `json:"signature"`
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
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	sig, _ := scheme.Sign(key, b)
	return data, hex.EncodeToString(sig)
}

func sign(key kyber.Scalar, store store.Storage, body *SignRequest, priv *share.PriShare) (interface{}, string, error) {
	available, err := keeper.Guard(store, key, body.Identity, body.Signature, body.Data)
	if err != nil {
		return nil, "", err
	}
	if available < 1 {
		return nil, "", ErrTooManyRequest
	}
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	partial, err := scheme.Sign(priv, []byte(body.Identity))
	data := map[string]interface{}{
		"partial": hex.EncodeToString(partial),
	}
	b, _ := json.Marshal(data)
	sch := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	sig, _ := sch.Sign(key, b)
	return data, hex.EncodeToString(sig), nil
}
