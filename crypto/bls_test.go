package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestBLSRoundTripAndConversions(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteG2()
	priv := suite.Scalar().Pick(random.New())
	pub := PublicKey(priv)
	msg := []byte("tip-test-message")

	sig, err := Sign(priv, msg)
	require.NoError(err)
	require.NoError(Verify(pub, msg, sig))
	require.Error(Verify(pub, []byte("tampered"), sig))

	privHex := hex.EncodeToString(PrivateKeyBytes(priv))
	parsedPriv, err := PrivateKeyFromHex(privHex)
	require.NoError(err)
	require.Equal(PrivateKeyBytes(priv), PrivateKeyBytes(parsedPriv))

	pubBytes := PublicKeyBytes(pub)
	require.Len(pubBytes, 128)

	parsedPubBytes, err := PubKeyFromBytes(pubBytes)
	require.NoError(err)
	require.True(pub.Equal(parsedPubBytes))

	pubString := PublicKeyString(pub)
	parsedPubString, err := PubKeyFromBase58(pubString)
	require.NoError(err)
	require.True(pub.Equal(parsedPubString))
}

func TestBLSParsingErrors(t *testing.T) {
	require := require.New(t)

	_, err := PrivateKeyFromHex("zz")
	require.Error(err)

	_, err = PubKeyFromBytes([]byte{1, 2, 3})
	require.Error(err)

	_, err = PubKeyFromBase58("not-a-public-key")
	require.Error(err)

	valid := PublicKeyString(PublicKey(bn256.NewSuiteG2().Scalar().Pick(random.New())))
	decoded, ver, err := base58.CheckDecode(valid)
	require.NoError(err)

	_, err = PubKeyFromBase58(base58.CheckEncode(decoded, ver+1))
	require.Error(err)
	require.Contains(err.Error(), "invalid version")
}
