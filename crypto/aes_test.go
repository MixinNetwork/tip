package crypto

import (
	"crypto/aes"
	"testing"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/assert"
)

func TestDH(t *testing.T) {
	assert := assert.New(t)

	suite := bn256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	d1 := DH(p2, s1)
	d2 := DH(p1, s2)
	assert.Equal(d1, d2)

	d1 = DH(p1, s1)
	d2 = DH(p2, s2)
	assert.NotEqual(d1, d2)
}

func TestEncDec(t *testing.T) {
	assert := assert.New(t)

	suite := bn256.NewSuiteG2()
	s1 := suite.Scalar().Pick(random.New())
	p1 := suite.Point().Mul(s1, nil)
	s2 := suite.Scalar().Pick(random.New())
	p2 := suite.Point().Mul(s2, nil)

	text := []byte("hello")
	b := Encrypt(p2, s1, text)
	assert.Len(b, aes.BlockSize*2)
	dec := Decrypt(p1, s2, b)
	assert.Equal(text, dec)
}
