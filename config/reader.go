package config

import (
	"os"

	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/pelletier/go-toml"
)

type Configuration struct {
	Messenger *messenger.MixinConfiguration `toml:"messenger"`
	Store     *store.BadgerConfiguration    `toml:"store"`
	Node      *signer.Configuration         `toml:"node"`
}

func ReadConfiguration(path string) (*Configuration, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf Configuration
	err = toml.Unmarshal(f, &conf)
	return &conf, err
}
