package tip

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/tip/crypto"
)

var httpClient *http.Client

func init() {
	httpClient = &http.Client{Timeout: 10 * time.Second}
}

type ResponseData struct {
	Commitments []string `json:"commitments,omitempty"`
	Identity    string   `json:"identity,omitempty"`
	Signers     []struct {
		Identity string `json:"identity"`
		Index    int    `json:"index"`
	} `json:"signers,omitempty"`
	Partial string `json:"partial,omitempty"`
}

type Response struct {
	Error *struct {
		Code        int    `json:"code"`
		Description string `json:"description"`
	} `json:"error"`
	Data      *ResponseData `json:"data"`
	Signature string        `json:"signature"`
}

func request(sp *signerPair, method string, data []byte) (*ResponseData, error) {
	req, err := http.NewRequest(method, sp.API, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Close = true

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error code %d", resp.StatusCode)
	}

	var body Response
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	if body.Error != nil {
		return nil, fmt.Errorf("error code %d", body.Error.Code)
	}

	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.PubKeyFromBase58(sp.Identity)
	if err != nil {
		return nil, err
	}
	data, err = json.Marshal(body.Data)
	if err != nil {
		return nil, err
	}
	err = crypto.Verify(pub, data, sig)
	if err != nil {
		return nil, err
	}

	return body.Data, nil
}
