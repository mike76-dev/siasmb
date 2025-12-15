package api

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/mike76-dev/siasmb/stores"
	"go.sia.tech/core/types"
)

// Store implements the database store.
type Store interface {
	IsBanned(host string) (bool, string, error)
	BanHost(host, reason string) error
	UnbanHost(host string) error
	ClearBans() error

	GetAccountByID(id int) (acc stores.Account, err error)
	FindAccount(username, workgroup string) (acc stores.Account, err error)
	AddAccount(acc stores.Account) error
	HasAccount(username, workgroup string) (bool, error)
	RemoveAccount(username, workgroup string) error
	RemoveAccounts(workgroup string) error

	GetAccessRights(share stores.Share, acc stores.Account) (ar stores.AccessRights, err error)
	SetAccessRights(ar stores.AccessRights) error
	RemoveAccessRights(share stores.Share, acc stores.Account) error
	ClearAccessRights(acc stores.Account) error

	RegisterShare(s stores.Share) error
	UnregisterShare(id types.Hash256) error
	GetShare(id types.Hash256, name string) (s stores.Share, err error)
	GetShares(acc stores.Account) (shares []stores.Share, err error)
	GetAccounts(sh stores.Share) (ars []stores.AccessRights, err error)
}

// API represents the API call handler.
type API struct {
	router   httprouter.Router
	store    Store
	stopChan chan struct{}
	rl       *ratelimiter
}

// NewAPI returns an initialized API object.
func NewAPI(s Store) *API {
	stopChan := make(chan struct{})
	return &API{
		store:    s,
		stopChan: stopChan,
		rl:       newRatelimiter(stopChan),
	}
}

// Close shuts down the handler.
func (api *API) Close() {
	close(api.stopChan)
}

// BasicAuth wraps an http.Handler to force a basic auth with a password.
func BasicAuth(password string) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if _, p, ok := req.BasicAuth(); !ok || p != password {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			h.ServeHTTP(w, req)
		})
	}
}

// ServeHTTP implements http.HandlerFunc.
func (api *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api.router.ServeHTTP(w, r)
}
