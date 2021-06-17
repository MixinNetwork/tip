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

type SignRequest struct {
	Identity string `json:"identity"`
	Nonce    string `json:"nonce"`
}

type Handler struct {
	store  store.Storage
	conf   *Configuration
	render *render.Render
}

type Configuration struct {
	Identity kyber.Point    `toml:"-"`
	Signers  []dkg.Node     `toml:"-"`
	Poly     []kyber.Point  `toml:"-"`
	Share    share.PriShare `toml:"-"`
	Port     int            `toml:"port"`
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
		hdr.httpError(w, http.StatusNotFound)
		return
	}

	if r.Method == "POST" {
		hdr.handleSign(w, r)
		return
	}

	hdr.handleInfo(w, r)
}

func (hdr *Handler) handleSign(w http.ResponseWriter, r *http.Request) {
	var body SignRequest
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		hdr.httpError(w, http.StatusBadRequest)
		return
	}
	data, err := sign(hdr.store, &body, &hdr.conf.Share)
	if err == ErrTooManyRequest {
		hdr.httpError(w, http.StatusTooManyRequests)
		return
	} else if err != nil {
		hdr.httpError(w, http.StatusInternalServerError)
		return
	}
	hdr.render.JSON(w, http.StatusOK, map[string]interface{}{"data": data})
}

func (hdr *Handler) handleInfo(w http.ResponseWriter, r *http.Request) {
	data := info(hdr.conf.Identity, hdr.conf.Signers, hdr.conf.Poly)
	hdr.render.JSON(w, http.StatusOK, map[string]interface{}{"data": data})
}

func (hdr *Handler) httpError(w http.ResponseWriter, code int) {
	hdr.render.JSON(w, code, map[string]interface{}{"error": map[string]interface{}{
		"code":        code,
		"description": http.StatusText(code),
	}})
}

func handleCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,Authorization,Mixin-Conversation-ID")
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
