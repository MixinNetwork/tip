package tip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var httpClient *http.Client

func init() {
	httpClient = &http.Client{Timeout: 10 * time.Second}
}

type ResponseData struct {
	Commitments []string `json:"commitments"`
	Identity    string   `json:"identity"`
	Signers     []struct {
		Identity string `json:"identity"`
		Index    int    `json:"index"`
	} `json:"signers"`
	Signature string `json:"signature"`
}

type Response struct {
	Error *struct {
		Code        int    `json:"code"`
		Description string `json:"description"`
	} `json:"error"`
	Data *ResponseData `json:"data"`
}

func request(api, method string, data []byte) (*ResponseData, error) {
	req, err := http.NewRequest(method, api, bytes.NewReader(data))
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
	return body.Data, nil
}
