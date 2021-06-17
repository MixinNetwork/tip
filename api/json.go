package api

import (
	"encoding/hex"

	"github.com/MixinNetwork/tip/keeper"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/sign/tbls"
)

func info(id kyber.Point, sigrs []dkg.Node, poly []kyber.Point) interface{} {
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
	return map[string]interface{}{
		"identity":    signer.PublicKeyString(id),
		"signers":     signers,
		"commitments": commitments,
	}
}

func sign(store store.Storage, body *SignRequest, priv *share.PriShare) (interface{}, error) {
	available, err := keeper.CheckLimit(store, body.Identity, body.Nonce)
	if err != nil {
		return nil, err
	}
	if available < 1 {
		return nil, ErrTooManyRequest
	}
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	partial, err := scheme.Sign(priv, []byte(body.Identity))
	return map[string]interface{}{
		"signature": hex.EncodeToString(partial),
	}, nil
}
