package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
	"github.com/unrolled/render"
)

type stubStore struct {
	watchFn func([]byte) ([]byte, time.Time, int, error)
}

func (s *stubStore) CheckPolyGroup([]byte) (bool, error) {
	return false, nil
}

func (s *stubStore) ReadPolyPublic() ([]byte, error) {
	return nil, nil
}

func (s *stubStore) ReadPolyShare() ([]byte, error) {
	return nil, nil
}

func (s *stubStore) WritePoly([]byte, []byte) error {
	return nil
}

func (s *stubStore) WriteAssignee([]byte, []byte) error {
	return nil
}

func (s *stubStore) ReadAssignor([]byte) ([]byte, error) {
	return nil, nil
}

func (s *stubStore) ReadAssignee([]byte) ([]byte, error) {
	return nil, nil
}

func (s *stubStore) CheckLimit([]byte, time.Duration, uint32, bool) (int, error) {
	return 0, nil
}

func (s *stubStore) CheckEphemeralNonce([]byte, []byte, uint64, time.Duration) (bool, error) {
	return false, nil
}

func (s *stubStore) RotateEphemeralNonce([]byte, []byte, uint64) error {
	return nil
}

func (s *stubStore) WriteSignRequest([]byte, []byte) (time.Time, int, error) {
	return time.Time{}, 0, nil
}

func (s *stubStore) Watch(key []byte) ([]byte, time.Time, int, error) {
	if s.watchFn != nil {
		return s.watchFn(key)
	}
	return nil, time.Time{}, 0, nil
}

func testScalar() kyber.Scalar {
	return bn256.NewSuiteG2().Scalar().Pick(random.New())
}

func testHandler(key kyber.Scalar, store *stubStore) *Handler {
	signers := []dkg.Node{
		{Index: 0, Public: crypto.PublicKey(key)},
		{Index: 1, Public: crypto.PublicKey(testScalar())},
	}
	poly := []kyber.Point{
		crypto.PublicKey(testScalar()),
		crypto.PublicKey(testScalar()),
	}
	return &Handler{
		store: store,
		conf: &Configuration{
			Key:     key,
			Signers: signers,
			Poly:    poly,
			Share:   &share.PriShare{I: 1},
			Port:    7000,
		},
		render: render.New(),
	}
}

func TestInfoSignsPayload(t *testing.T) {
	require := require.New(t)

	key := testScalar()
	signers := []dkg.Node{
		{Index: 0, Public: crypto.PublicKey(key)},
		{Index: 1, Public: crypto.PublicKey(testScalar())},
	}
	poly := []kyber.Point{
		crypto.PublicKey(testScalar()),
		crypto.PublicKey(testScalar()),
	}

	data, sigHex := info(key, signers, poly)
	body, ok := data.(map[string]any)
	require.True(ok)
	require.Equal(crypto.PublicKeyString(crypto.PublicKey(key)), body["identity"])
	require.Len(body["signers"], len(signers))
	require.Len(body["commitments"], len(poly))

	rawSig, err := hex.DecodeString(sigHex)
	require.NoError(err)

	payload, err := json.Marshal(data)
	require.NoError(err)
	require.NoError(crypto.Verify(crypto.PublicKey(key), payload, rawSig))
}

func TestWatchRejectsInvalidWatcher(t *testing.T) {
	require := require.New(t)

	_, _, err := watch(&stubStore{}, "bad-watcher")
	require.Error(err)
	require.Contains(err.Error(), "invalid watcher")
}

func TestWatchReturnsStoreValues(t *testing.T) {
	require := require.New(t)

	wantWatcher := bytes.Repeat([]byte{0x7f}, 32)
	wantAssignor := []byte("assignor")
	wantGenesis := time.Unix(1700000000, 123)
	store := &stubStore{
		watchFn: func(key []byte) ([]byte, time.Time, int, error) {
			require.Equal(wantWatcher, key)
			return wantAssignor, wantGenesis, 3, nil
		},
	}

	genesis, counter, err := watch(store, hex.EncodeToString(wantWatcher))
	require.NoError(err)
	require.True(wantGenesis.Equal(genesis))
	require.Equal(3, counter)
}

func TestServeHTTPGetRoot(t *testing.T) {
	require := require.New(t)

	key := testScalar()
	hdr := testHandler(key, &stubStore{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	hdr.ServeHTTP(rec, req)

	require.Equal(http.StatusOK, rec.Code)

	var body struct {
		Data      map[string]any `json:"data"`
		Signature string         `json:"signature"`
		Version   string         `json:"version"`
	}
	require.NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal("v0.2.0", body.Version)
	require.Equal(crypto.PublicKeyString(crypto.PublicKey(key)), body.Data["identity"])

	rawSig, err := hex.DecodeString(body.Signature)
	require.NoError(err)
	payload, err := json.Marshal(body.Data)
	require.NoError(err)
	require.NoError(crypto.Verify(crypto.PublicKey(key), payload, rawSig))
}

func TestServeHTTPHandlesErrorsAndWatchRequests(t *testing.T) {
	require := require.New(t)

	watcher := bytes.Repeat([]byte{0x42}, 32)
	genesis := time.Unix(1701000000, 0)
	store := &stubStore{
		watchFn: func(key []byte) ([]byte, time.Time, int, error) {
			require.Equal(watcher, key)
			return []byte("assignor"), genesis, 9, nil
		},
	}
	hdr := testHandler(testScalar(), store)

	notFoundReq := httptest.NewRequest(http.MethodGet, "/missing", nil)
	notFoundRec := httptest.NewRecorder()
	hdr.ServeHTTP(notFoundRec, notFoundReq)
	require.Equal(http.StatusNotFound, notFoundRec.Code)

	invalidJSONReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{"))
	invalidJSONRec := httptest.NewRecorder()
	hdr.ServeHTTP(invalidJSONRec, invalidJSONReq)
	require.Equal(http.StatusBadRequest, invalidJSONRec.Code)

	watchReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"action":"WATCH","watcher":"`+hex.EncodeToString(watcher)+`"}`))
	watchRec := httptest.NewRecorder()
	hdr.ServeHTTP(watchRec, watchReq)
	require.Equal(http.StatusOK, watchRec.Code)

	var watchBody struct {
		Genesis time.Time `json:"genesis"`
		Counter int       `json:"counter"`
	}
	require.NoError(json.Unmarshal(watchRec.Body.Bytes(), &watchBody))
	require.True(genesis.Equal(watchBody.Genesis))
	require.Equal(9, watchBody.Counter)

	invalidActionReq := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"action":"NOPE"}`))
	invalidActionRec := httptest.NewRecorder()
	hdr.ServeHTTP(invalidActionRec, invalidActionReq)
	require.Equal(http.StatusBadRequest, invalidActionRec.Code)
}

func TestHandleCORSPassesThroughAndHandlesOptions(t *testing.T) {
	require := require.New(t)

	called := false
	handler := handleCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusCreated)
	}))

	optionsReq := httptest.NewRequest(http.MethodOptions, "/", nil)
	optionsReq.Header.Set("Origin", "https://example.com")
	optionsRec := httptest.NewRecorder()
	handler.ServeHTTP(optionsRec, optionsReq)

	require.False(called)
	require.Equal(http.StatusOK, optionsRec.Code)
	require.Equal("https://example.com", optionsRec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal("Content-Type,X-Request-ID", optionsRec.Header().Get("Access-Control-Allow-Headers"))

	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getReq.Header.Set("Origin", "https://example.com")
	getRec := httptest.NewRecorder()
	handler.ServeHTTP(getRec, getReq)

	require.True(called)
	require.Equal(http.StatusCreated, getRec.Code)
	require.Equal("https://example.com", getRec.Header().Get("Access-Control-Allow-Origin"))
}

func TestMaxBytesReaderAllowsLargeSignRequests(t *testing.T) {
	require := require.New(t)

	hdr := testHandler(testScalar(), &stubStore{})

	// A SIGN request with assignee+rotate fields produces ~1637 bytes.
	// Use 180 for identity (base58 public key) and 1200 for encrypted data
	// to create a ~1600-byte body that would fail under the old 1024 limit.
	payload := `{"action":"SIGN","identity":"` + string(bytes.Repeat([]byte("A"), 180)) + `","data":"` + string(bytes.Repeat([]byte("B"), 1200)) + `","signature":"abcd","watcher":"abcd"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	hdr.ServeHTTP(rec, req)

	// The request should be decoded (not rejected by MaxBytesReader).
	// It will fail downstream at signature/data validation, but NOT at JSON decode.
	// A StatusBadRequest from MaxBytesReader would indicate the limit is too small.
	require.NotEqual(http.StatusBadRequest, rec.Code)
}

func TestMaxBytesReaderRejectsOversizedRequests(t *testing.T) {
	require := require.New(t)

	hdr := testHandler(testScalar(), &stubStore{})

	// A body larger than 4096 bytes must be rejected
	payload := `{"action":"SIGN","data":"` + string(bytes.Repeat([]byte("X"), 4096)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(payload))
	rec := httptest.NewRecorder()
	hdr.ServeHTTP(rec, req)

	require.Equal(http.StatusBadRequest, rec.Code)
}
