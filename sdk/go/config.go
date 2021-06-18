package tip

import (
	"encoding/json"

	"github.com/MixinNetwork/tip/signer"
)

type signerPair struct {
	Identity string `json:"identity"`
	API      string `json:"api"`
}

type Configuration struct {
	Commitments []string      `json:"commitments"`
	Signers     []*signerPair `json:"signers"`
}

func LoadConfigurationJSON(data string) (*Configuration, error) {
	var conf Configuration
	err := json.Unmarshal([]byte(data), &conf)
	if err != nil {
		return nil, err
	}
	return &conf, conf.validate()
}

func (conf *Configuration) validate() error {
	if len(conf.Commitments) != len(conf.Signers)*2/3+1 {
		return ErrInvalidConfiguration
	}
	for _, c := range conf.Commitments {
		_, err := signer.PubKeyFromBase58(c)
		if err != nil {
			return ErrInvalidConfiguration
		}
	}
	return nil
}
