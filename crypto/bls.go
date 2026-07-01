package crypto

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/address/v2/base58"
	"go.dedis.ch/kyber/v4"
	"go.dedis.ch/kyber/v4/pairing/bn256"
	"go.dedis.ch/kyber/v4/sign/bdn"
)

const (
	KeyVersion = 'T'
)

func Sign(scalar kyber.Scalar, msg []byte) ([]byte, error) {
	scheme := bdn.NewSchemeOnG1(bn256.NewSuiteG2())
	return scheme.Sign(scalar, msg)
}

func Verify(pub kyber.Point, msg, sig []byte) error {
	scheme := bdn.NewSchemeOnG1(bn256.NewSuiteG2())
	return scheme.Verify(pub, msg, sig)
}

func PrivateKeyFromHex(s string) (kyber.Scalar, error) {
	seed, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().SetBytes(seed)
	return scalar, nil
}

func PrivateKeyBytes(scalar kyber.Scalar) []byte {
	b, err := scalar.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func PublicKey(scalar kyber.Scalar) kyber.Point {
	suite := bn256.NewSuiteG2()
	return suite.Point().Mul(scalar, nil)
}

func PublicKeyString(point kyber.Point) string {
	b := PublicKeyBytes(point)
	return base58.CheckEncode(b, KeyVersion)
}

func PublicKeyBytes(point kyber.Point) []byte {
	b, err := point.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func PubKeyFromBytes(b []byte) (kyber.Point, error) {
	suite := bn256.NewSuiteG2()
	point := suite.G2().Point()
	err := point.UnmarshalBinary(b)
	return point, err
}

func PubKeyFromBase58(s string) (kyber.Point, error) {
	b, ver, err := base58.CheckDecode(s)
	if err != nil {
		return nil, err
	}
	if ver != KeyVersion {
		return nil, fmt.Errorf("invalid version %d", ver)
	}
	return PubKeyFromBytes(b)
}
