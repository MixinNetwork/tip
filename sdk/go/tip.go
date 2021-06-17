package tip

import (
	"encoding/hex"
	"encoding/json"

	"github.com/MixinNetwork/tip/signer"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/tbls"
)

type Client struct {
	commitments []kyber.Point
	signers     []*signerConf
}

func NewClient(conf *Configuration) (*Client, error) {
	err := conf.validate()
	if err != nil {
		return nil, err
	}

	cli := &Client{signers: conf.Signers}
	for _, c := range conf.Commitments {
		point, _ := signer.PubKeyFromBase58(c)
		cli.commitments = append(cli.commitments, point)
	}

	for _, s := range conf.Signers {
		res, err := request(s.API, "GET", nil)
		if err != nil {
			return nil, err
		}
		if res.Identity != s.Identity {
			return nil, ErrInvalidConfiguration
		}
		if len(res.Signers) != len(conf.Signers) {
			return nil, ErrInvalidConfiguration
		}
		for i, s := range res.Signers {
			if conf.Signers[i].Identity != s.Identity {
				return nil, ErrInvalidConfiguration
			}
		}
		if len(res.Commitments) != len(conf.Commitments) {
			return nil, ErrInvalidConfiguration
		}
		for i, c := range res.Commitments {
			if conf.Commitments[i] != c {
				return nil, ErrInvalidConfiguration
			}
		}
	}
	return cli, nil
}

func (c *Client) Sign(id string) ([]byte, error) {
	data, _ := json.Marshal(map[string]string{
		"identity": id,
		"nonce":    "1024",
	})
	var partials [][]byte
	for _, s := range c.signers {
		res, err := request(s.API, "POST", data)
		if err != nil {
			return nil, err
		}
		par, err := hex.DecodeString(res.Signature)
		if err != nil {
			return nil, err
		}
		partials = append(partials, par)
	}
	suite := bn256.NewSuiteG2()
	scheme := tbls.NewThresholdSchemeOnG1(bn256.NewSuiteG2())
	pub := share.NewPubPoly(suite, suite.Point().Base(), c.commitments)
	return scheme.Recover(pub, []byte(id), partials, len(c.commitments), len(c.signers))
}
