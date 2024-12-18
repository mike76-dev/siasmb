package stores

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// AccessRights describes the access policies of a user account.
type AccessRights struct {
	Username      string `yaml:"username"`
	ReadAccess    bool   `yaml:"read"`
	WriteAccess   bool   `yaml:"write"`
	DeleteAccess  bool   `yaml:"delete"`
	ExecuteAccess bool   `yaml:"execute"`
}

// Share represents a renterd bucket, which is mounted as a remote share.
type Share struct {
	Name       string         `yaml:"name"`
	ServerName string         `yaml:"serverName"`
	Password   string         `yaml:"apiPassword,omitempty"`
	Bucket     string         `yaml:"bucket,omitempty"`
	Policies   []AccessRights `yaml:"policies,omitempty"`
	Remark     string         `yaml:"remark,omitempty"`
}

// SharesStore lists all available shares.
type SharesStore struct {
	Shares []Share `yaml:"shares,omitempty"`
}

// NewSharesStore returns an initialized SharesStore.
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

// FlagsFromAccessRights converts an AccessRights structure into SMB2 flags.
func FlagsFromAccessRights(ar AccessRights) uint32 {
	var flags uint32
	if ar.ReadAccess {
		flags |= 0x00120089 // FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
	}

	if ar.WriteAccess {
		flags |= 0x000c0116 // FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER
	}

	if ar.DeleteAccess {
		flags |= 0x00010040 // FILE_DELETE_CHILD | DELETE
	}

	if ar.ExecuteAccess {
		flags |= 0x00000020 // FILE_EXECUTE
	}

	return flags
}
