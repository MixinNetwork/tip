package tip

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/tbls"
	"golang.org/x/crypto/sha3"
)

type Client struct {
	commitments []kyber.Point
	signers     []*signerPair
}

func NewClient(conf *Configuration) (*Client, []*signerPair, error) {
	err := conf.validate()
	if err != nil {
		return nil, nil, err
	}

	cli := &Client{signers: conf.Signers}
	for _, c := range conf.Commitments {
		point, _ := crypto.PubKeyFromBase58(c)
		cli.commitments = append(cli.commitments, point)
	}

	var evicted []*signerPair
	for _, s := range conf.Signers {
		res, err := request(s, "GET", nil)
		if err != nil {
			evicted = append(evicted, s)
			continue
		}
		if res.Identity != s.Identity {
			evicted = append(evicted, s)
			continue
		}
		if len(res.Signers) != len(conf.Signers) {
			evicted = append(evicted, s)
			continue
		}
		for i, rs := range res.Signers {
			if conf.Signers[i].Identity != rs.Identity {
				evicted = append(evicted, s)
				break
			}
		}
		if len(res.Commitments) != len(conf.Commitments) {
			evicted = append(evicted, s)
			continue
		}
		for i, c := range res.Commitments {
			if conf.Commitments[i] != c {
				evicted = append(evicted, s)
				break
			}
		}
	}

	if sc := len(conf.Signers) - len(evicted); sc < len(conf.Commitments) {
		return nil, evicted, fmt.Errorf("not enough signers %d %d", sc, len(conf.Commitments))
	}
	return cli, evicted, nil
}

func (c *Client) Sign(ks, ephemeral string, nonce, grace int64, rotate, assignee, watcher string) ([]byte, []*signerPair, error) {
	key, err := crypto.PrivateKeyFromHex(ks)
	if err != nil {
		return nil, nil, err
	}
	_, err = crypto.PrivateKeyFromHex(ephemeral)
	if err != nil {
		return nil, nil, err
	}
	if rotate != "" {
		_, err = crypto.PrivateKeyFromHex(rotate)
		if err != nil {
			return nil, nil, err
		}
	}

	var assignor []byte
	var partials [][]byte
	var evicted []*signerPair
	pam := make(map[string][]byte)
	acm := make(map[string]int)
	for _, s := range c.signers {
		data := sign(key, s.Identity, ephemeral, uint64(nonce), uint64(grace), rotate, assignee, watcher)
		res, err := request(s, "POST", data)
		if err != nil {
			evicted = append(evicted, s)
			continue
		}
		enc, err := hex.DecodeString(res.Cipher)
		if err != nil {
			evicted = append(evicted, s)
			continue
		}
		if len(enc) < 32 {
			evicted = append(evicted, s)
			continue
		}
		pub, err := crypto.PubKeyFromBase58(s.Identity)
		if err != nil {
			panic(err)
		}
		dec := crypto.Decrypt(pub, key, enc)
		if len(dec) != 8+66+128+8+8 {
			evicted = append(evicted, s)
			continue
		}
		if uint64(nonce) != binary.BigEndian.Uint64(dec[:8]) {
			evicted = append(evicted, s)
			continue
		}
		p, a := dec[8:74], dec[74:202]
		as := hex.EncodeToString(a)
		pam[hex.EncodeToString(p)] = a
		acm[as] = acm[as] + 1
	}
	var amc int
	for a, c := range acm {
		if c <= amc {
			continue
		}
		assignor, _ = hex.DecodeString(a)
		amc = c
	}
	for p, a := range pam {
		if bytes.Compare(a, assignor) != 0 {
			continue
		}
		partial, _ := hex.DecodeString(p)
		partials = append(partials, partial)
	}

	if len(partials) < len(c.commitments) {
		return nil, evicted, fmt.Errorf("not enough partials %d %d", len(partials), len(c.commitments))
	}
	suite := bn256.NewSuiteG2()
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	poly := share.NewPubPoly(suite, suite.Point().Base(), c.commitments)
	sig, err := scheme.Recover(poly, assignor, partials, len(c.commitments), len(c.signers))
	if err != nil {
		return nil, evicted, err
	}
	err = crypto.Verify(poly.Commit(), assignor, sig)
	if err != nil {
		return nil, evicted, err
	}
	return sig, evicted, nil
}

func sign(key kyber.Scalar, nodeId, ephemeral string, nonce, grace uint64, rotate, assignee, watcher string) []byte {
	pkey := crypto.PublicKey(key)
	esum := sha3.Sum256(append([]byte(ephemeral), nodeId...))
	msg := crypto.PublicKeyBytes(pkey)
	msg = append(msg, esum[:]...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	data := map[string]interface{}{
		"identity":  crypto.PublicKeyString(pkey),
		"ephemeral": hex.EncodeToString(esum[:]),
		"watcher":   watcher,
		"nonce":     nonce,
		"grace":     grace,
	}
	if rotate != "" {
		rsum := sha3.Sum256(append([]byte(rotate), nodeId...))
		msg = append(msg, rsum[:]...)
		data["rotate"] = hex.EncodeToString(rsum[:])
	}
	if len(assignee) > 0 {
		as, _ := crypto.PrivateKeyFromHex(assignee)
		ap := crypto.PublicKey(as)
		ab := crypto.PublicKeyBytes(ap)
		sig, _ := crypto.Sign(as, ab)
		ab = append(ab, sig...)
		msg = append(msg, ab...)
		data["assignee"] = hex.EncodeToString(ab)
	}
	b, _ := json.Marshal(data)
	spub, err := crypto.PubKeyFromBase58(nodeId)
	if err != nil {
		panic(err)
	}
	cipher := crypto.Encrypt(spub, key, b)
	sig, _ := crypto.Sign(key, msg)
	b, _ = json.Marshal(map[string]interface{}{
		"action":    "SIGN",
		"identity":  crypto.PublicKeyString(pkey),
		"data":      base64.RawURLEncoding.EncodeToString(cipher[:]),
		"signature": hex.EncodeToString(sig),
		"watcher":   watcher,
	})
	return b
}
