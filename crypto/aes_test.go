package crypto

import (
	"testing"

	"github.com/MixinNetwork/tip/crypto/en256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/assert"
)

func TestDH(t *testing.T) {
	assert := assert.New(t)

	suite := en256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	d1 := ecdh(p2, s1)
	d2 := ecdh(p1, s2)
	assert.Equal(d1, d2)

	d1 = ecdh(p1, s1)
	d2 = ecdh(p2, s2)
	assert.NotEqual(d1, d2)

	i1 := ecdh(en256.NewSuiteG2().Point(), s1)
	i2 := ecdh(en256.NewSuiteG2().Point(), s2)
	assert.NotEqual(i1, i2)
}

func TestEncDec(t *testing.T) {
	assert := assert.New(t)

	suite := en256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	text := []byte("hello")
	b := Encrypt(p2, s1, text)
	assert.Len(b, 12+16+len(text))
	dec := Decrypt(p1, s2, b)
	assert.Equal(text, dec)
}
