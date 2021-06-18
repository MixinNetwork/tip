package tip

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/MixinNetwork/tip/signer"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
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
		point, _ := signer.PubKeyFromBase58(c)
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
		return nil, evicted, fmt.Errorf("not enought signers %d %d", sc, len(conf.Commitments))
	}
	return cli, evicted, nil
}

func (c *Client) Sign(id string) ([]byte, []*signerPair, error) {
	data, _ := json.Marshal(map[string]string{
		"identity": id,
		"nonce":    "1024",
	})
	var evicted []*signerPair
	var partials [][]byte
	for _, s := range c.signers {
		res, err := request(s, "POST", data)
		if err != nil {
			evicted = append(evicted, s)
			continue
		}
		par, err := hex.DecodeString(res.Partial)
		if err != nil {
			evicted = append(evicted, s)
			continue
		}
		partials = append(partials, par)
	}
	if len(partials) < len(c.commitments) {
		return nil, evicted, fmt.Errorf("not enought partials %d %d", len(partials), len(c.commitments))
	}
	suite := bn256.NewSuiteG2()
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	pub := share.NewPubPoly(suite, suite.Point().Base(), c.commitments)
	sig, err := scheme.Recover(pub, []byte(id), partials, len(c.commitments), len(c.signers))
	if err != nil {
		return nil, evicted, err
	}
	err = bls.NewSchemeOnG1(suite).Verify(pub.Commit(), []byte(id), sig)
	if err != nil {
		return nil, evicted, err
	}
	return sig, evicted, nil
}
