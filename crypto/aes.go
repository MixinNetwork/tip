package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"golang.org/x/crypto/sha3"
)

func DH(point kyber.Point, scalar kyber.Scalar) []byte {
	suite := bn256.NewSuiteG2()
	point = suite.Point().Mul(scalar, point)

	b := PublicKeyBytes(point)
	sum := sha3.Sum256(b)
	return sum[:]
}

func Decrypt(pub kyber.Point, priv kyber.Scalar, b []byte) []byte {
	secret := DH(pub, priv)
	block, _ := aes.NewCipher(secret)
	iv := b[:aes.BlockSize]
	b = b[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(b, b)
	plen := int(b[len(b)-1])
	return b[:len(b)-plen]
}

func Encrypt(pub kyber.Point, priv kyber.Scalar, b []byte) []byte {
	secret := DH(pub, priv)
	plen := aes.BlockSize - len(b)%aes.BlockSize
	padd := bytes.Repeat([]byte{byte(plen)}, plen)
	b = append(b, padd...)
	block, err := aes.NewCipher(secret)
	if err != nil {
		panic(err)
	}
	encrypted := make([]byte, aes.BlockSize+len(b))
	iv := encrypted[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted[aes.BlockSize:], b)
	return encrypted
}
