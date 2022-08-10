package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/tip/logger"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/unrolled/render"
)

type Handler struct {
	store  store.Storage
	conf   *Configuration
	render *render.Render
}

type Configuration struct {
	Key     kyber.Scalar    `toml:"-"`
	Signers []dkg.Node      `toml:"-"`
	Poly    []kyber.Point   `toml:"-"`
	Share   *share.PriShare `toml:"-"`
	Port    int             `toml:"port"`
}

func NewServer(store store.Storage, conf *Configuration) *http.Server {
	hdr := &Handler{
		store:  store,
		render: render.New(),
		conf:   conf,
	}
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", conf.Port),
		Handler:      handleCORS(hdr),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return server
}

func (hdr *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Info(*r)
	defer handlePanic(w, r)

	if r.URL.Path != "/" {
		hdr.error(w, r, http.StatusNotFound)
		return
	}

	if r.Method == "POST" {
		hdr.handle(w, r)
		return
	}

	data, sig := info(hdr.conf.Key, hdr.conf.Signers, hdr.conf.Poly)
	hdr.json(w, r, http.StatusOK, map[string]interface{}{"data": data, "signature": sig})
}

func (hdr *Handler) handle(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		hdr.error(w, r, http.StatusBadRequest)
		return
	}
	switch body.Action {
	case "SIGN":
		data, sig, err := sign(hdr.conf.Key, hdr.store, &body, hdr.conf.Share)
		if err == ErrTooManyRequest {
			hdr.error(w, r, http.StatusTooManyRequests)
			return
		} else if err != nil {
			hdr.error(w, r, http.StatusInternalServerError)
			return
		}
		hdr.json(w, r, http.StatusOK, map[string]interface{}{"data": data, "signature": sig})
	case "WATCH":
		genesis, counter, err := watch(hdr.store, body.Watcher)
		if err != nil {
			hdr.error(w, r, http.StatusInternalServerError)
			return
		}
		hdr.json(w, r, http.StatusOK, map[string]interface{}{"genesis": genesis, "counter": counter})
	default:
		hdr.error(w, r, http.StatusBadRequest)
	}
}

func (hdr *Handler) error(w http.ResponseWriter, r *http.Request, code int) {
	hdr.json(w, r, code, map[string]interface{}{"error": map[string]interface{}{
		"code":        code,
		"description": http.StatusText(code),
	}})
}

func (hdr *Handler) json(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	id := r.Header.Get("X-Request-ID")
	logger.Info(r.Method, r.URL, id, code, data)
	hdr.render.JSON(w, code, data)
}

func handleCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,POST,DELETE")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == "OPTIONS" {
			render.New().JSON(w, http.StatusOK, map[string]interface{}{})
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}

func handlePanic(w http.ResponseWriter, r *http.Request) {
	rcv := recover()
	if rcv == nil {
		return
	}
	err := fmt.Sprint(rcv)
	logger.Error(err)
}
