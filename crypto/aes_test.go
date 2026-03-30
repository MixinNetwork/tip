package crypto

import (
	"testing"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func TestDH(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	d1 := ecdh(p2, s1)
	d2 := ecdh(p1, s2)
	require.Equal(d1, d2)

	d1 = ecdh(p1, s1)
	d2 = ecdh(p2, s2)
	require.NotEqual(d1, d2)

	i1 := ecdh(bn256.NewSuiteG2().Point(), s1)
	i2 := ecdh(bn256.NewSuiteG2().Point(), s2)
	require.NotEqual(i1, i2)
}

func TestEncDec(t *testing.T) {
	require := require.New(t)

	suite := bn256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	text := []byte("hello")
	b := EncryptECDH(p2, s1, text)
	require.Len(b, 12+16+len(text))
	dec := DecryptECDH(p1, s2, b)
	require.Equal(text, dec)
}

func TestDecryptShortInput(t *testing.T) {
	require := require.New(t)

	secret := make([]byte, 32)

	require.Nil(Decrypt(secret, nil))
	require.Nil(Decrypt(secret, []byte{}))
	require.Nil(Decrypt(secret, []byte{1, 2, 3}))
	require.Nil(Decrypt(secret, make([]byte, 11)))
	require.Nil(Decrypt(secret, make([]byte, 27)))
}
