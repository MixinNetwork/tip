package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/util/random"
	"golang.org/x/crypto/sha3"
)

func ecdh(point kyber.Point, scalar kyber.Scalar) []byte {
	suite := bn256.NewSuiteG2()
	if point.Equal(suite.Point()) {
		r := suite.Scalar().Pick(random.New())
		point = point.Mul(r, nil)
	}
	point = suite.Point().Mul(scalar, point)

	b := PublicKeyBytes(point)
	sum := sha3.Sum256(b)
	return sum[:]
}

func Decrypt(secret, b []byte) []byte {
	aes, _ := aes.NewCipher(secret)
	aead, _ := cipher.NewGCM(aes)
	nonce := b[:aead.NonceSize()]
	cipher := b[aead.NonceSize():]
	d, _ := aead.Open(nil, nonce, cipher, nil)
	return d
}

func Encrypt(secret, b []byte) []byte {
	aes, err := aes.NewCipher(secret)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	cipher := aead.Seal(nil, nonce, b, nil)
	return append(nonce, cipher...)
}

func DecryptECDH(pub kyber.Point, priv kyber.Scalar, b []byte) []byte {
	secret := ecdh(pub, priv)
	return Decrypt(secret, b)
}

func EncryptECDH(pub kyber.Point, priv kyber.Scalar, b []byte) []byte {
	secret := ecdh(pub, priv)
	return Encrypt(secret, b)
}
