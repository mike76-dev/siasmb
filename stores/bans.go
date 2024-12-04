package stores

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type BansStore struct {
	Bans map[string]string
	Mu   sync.Mutex
	dir  string
}

type ban struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

func NewJSONBansStore(dir string) (*BansStore, error) {
	bs := &BansStore{
		Bans: make(map[string]string),
		dir:  dir,
	}
	err := bs.load()
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func (bs *BansStore) load() error {
	var bans []ban
	if js, err := os.ReadFile(filepath.Join(bs.dir, "bans.json")); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	} else if err := json.Unmarshal(js, &bans); err != nil {
		return err
	}
	for _, ban := range bans {
		bs.Bans[ban.Host] = ban.Reason
	}
	return nil
}

func (bs *BansStore) Save() error {
	var bans []ban
	for host, reason := range bs.Bans {
		bans = append(bans, ban{
			Host:   host,
			Reason: reason,
		})
	}
	file, err := os.OpenFile(filepath.Join(bs.dir, "bans.json"), os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.MarshalIndent(bans, "", "\t")
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return file.Sync()
}
