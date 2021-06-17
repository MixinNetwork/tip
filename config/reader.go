package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/MixinNetwork/tip/api"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/pelletier/go-toml"
)

type Configuration struct {
	API       *api.Configuration            `toml:"api"`
	Messenger *messenger.MixinConfiguration `toml:"messenger"`
	Store     *store.BadgerConfiguration    `toml:"store"`
	Node      *signer.Configuration         `toml:"node"`
}

func ReadConfiguration(path string) (*Configuration, error) {
	if strings.HasPrefix(path, "~/") {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, (path)[2:])
	}
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf Configuration
	err = toml.Unmarshal(f, &conf)
	return &conf, err
}
