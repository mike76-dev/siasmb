package stores

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type account struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type persistData struct {
	Accounts []account `json:"accounts"`
}

// AccountStore represents a username-password database.
type AccountStore struct {
	Accounts map[string]string
}

// NewJSONAccountStore returns an initialized AccountStore.
func NewJSONAccountStore(dir string) (*AccountStore, error) {
	as := &AccountStore{
		Accounts: make(map[string]string),
	}
	err := as.load(dir)
	if err != nil {
		return nil, err
	}
	return as, nil
}

func (as *AccountStore) load(dir string) error {
	var p persistData
	if js, err := os.ReadFile(filepath.Join(dir, "accounts.json")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if err := json.Unmarshal(js, &p); err != nil {
		return err
	}
	for _, a := range p.Accounts {
		as.Accounts[a.Username] = a.Password
	}
	return nil
}
