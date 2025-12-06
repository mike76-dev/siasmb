package stores

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// DatabaseConfig lists all the fields needed to connect to a PostgreSQL database.
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"sslMode"`
}

// String returns a connection string.
func (dc DatabaseConfig) String() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s", dc.Host, dc.Port, dc.User, dc.Password, dc.Database, dc.SSLMode)
}

// Config lists the config fields.
type Config struct {
	Mode           string         `yaml:"mode"`
	MaxConnections int            `yaml:"maxConnections"`
	APIPort        int            `yaml:"apiPort"`
	Database       DatabaseConfig `yaml:"database"`
}

// ReadConfig tries to read the config from the specified directory.
func ReadConfig(dir string) (cfg Config, err error) {
	path := filepath.Join(dir, "siasmb.yml")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	err = dec.Decode(&cfg)
	return
}
