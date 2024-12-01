package stores

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type BansStore struct {
	Bans map[string]struct{}
}

func NewJSONBansStore(dir string) (*BansStore, error) {
	bs := &BansStore{
		Bans: make(map[string]struct{}),
	}
	err := bs.load(dir)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func (bs *BansStore) load(dir string) error {
	var bans []string
	if js, err := os.ReadFile(filepath.Join(dir, "bans.json")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if err := json.Unmarshal(js, &bans); err != nil {
		return err
	}
	for _, ban := range bans {
		bs.Bans[ban] = struct{}{}
	}
	return nil
}
