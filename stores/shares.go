package stores

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type AccessRights struct {
	Username      string `yaml:"username"`
	ReadAccess    bool   `yaml:"read"`
	WriteAccess   bool   `yaml:"write"`
	DeleteAccess  bool   `yaml:"delete"`
	ExecuteAccess bool   `yaml:"execute"`
}

type Share struct {
	Name       string         `yaml:"name"`
	ServerName string         `yaml:"serverName"`
	Password   string         `yaml:"apiPassword,omitempty"`
	Bucket     string         `yaml:"bucket,omitempty"`
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

func FlagsFromAccessRights(ar AccessRights) uint32 {
	var flags uint32
	if ar.ReadAccess {
		flags |= 0x00120089
	}

	if ar.WriteAccess {
		flags |= 0x000c0116
	}

	if ar.DeleteAccess {
		flags |= 0x00010040
	}

	if ar.ExecuteAccess {
		flags |= 0x00000020
	}

	return flags
}
