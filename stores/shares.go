package stores

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type AccessRights struct {
	Username string `yaml:"username"`
	Flags    uint32 `yaml:"flags"`
}

type Share struct {
	Name       string         `yaml:"name"`
	ServerName string         `yaml:"serverName"`
	Policies   []AccessRights `yaml:"policies,omitempty"`
	Remark     string         `yaml:"remark,omitempty"`
}

type SharesStore struct {
	Shares []Share `yaml:"shares,omitempty"`
}

func NewSharesStore(dir string) (*SharesStore, error) {
	path := filepath.Join(dir, "shares.yml")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	ss := &SharesStore{}
	if err := dec.Decode(ss); err != nil {
		return nil, err
	}

	return ss, nil
}
