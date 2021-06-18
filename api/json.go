package api

import (
	"encoding/hex"
	"encoding/json"

	"github.com/MixinNetwork/tip/keeper"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
)

type SignRequest struct {
	Identity  string `json:"identity"`
	Ephemeral string `json:"ephemeral"`
	Signature string `json:"signature"`
	Nonce     int64  `json:"nonce"`
}

func info(key kyber.Scalar, sigrs []dkg.Node, poly []kyber.Point) (interface{}, string) {
	signers := make([]map[string]interface{}, len(sigrs))
	for i, s := range sigrs {
		signers[i] = map[string]interface{}{
			"index":    s.Index,
			"identity": signer.PublicKeyString(s.Public),
		}
	}
	commitments := make([]string, len(poly))
	for i, c := range poly {
		commitments[i] = signer.PublicKeyString(c)
	}
	id := signer.PublicKey(key)
	data := map[string]interface{}{
		"identity":    signer.PublicKeyString(id),
		"signers":     signers,
		"commitments": commitments,
	}
	b, _ := json.Marshal(data)
	scheme := bls.NewSchemeOnG1(bn256.NewSuiteG2())
	sig, _ := scheme.Sign(key, b)
	return data, hex.EncodeToString(sig)
}

func sign(key kyber.Scalar, store store.Storage, body *SignRequest, priv *share.PriShare) (interface{}, string, error) {
	available, err := keeper.Check(store, body.Identity, body.Ephemeral, body.Signature, body.Nonce)
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
