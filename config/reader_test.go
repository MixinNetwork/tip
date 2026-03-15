package config

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const validConfigurationTOML = `
[api]
port = 7000

[messenger]
user = "user-id"
session = "session-id"
key = "private-key"
buffer = 8
conversation = "conversation-id"

[store]
dir = "/tmp/tip-store"

[node]
key = "0123456789abcdef"
signers = ["signer-a", "signer-b", "signer-c"]
`

func TestReadConfigurationExpandsHome(t *testing.T) {
	require := require.New(t)

	usr, err := user.Current()
	require.NoError(err)

	dir, err := os.MkdirTemp(filepath.Join(usr.HomeDir, "tip"), "config-home-")
	require.NoError(err)
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	path := filepath.Join(dir, "config.toml")
	require.NoError(os.WriteFile(path, []byte(validConfigurationTOML), 0o600))

	tildePath := filepath.Join("~", "tip", filepath.Base(dir), "config.toml")
	conf, err := ReadConfiguration(tildePath)
	require.NoError(err)
	require.NotNil(conf)
	require.Equal(7000, conf.API.Port)
	require.Equal("user-id", conf.Messenger.UserId)
	require.Equal("conversation-id", conf.Messenger.ConversationId)
	require.Equal("/tmp/tip-store", conf.Store.Dir)
	require.Equal("0123456789abcdef", conf.Node.Key)
	require.Equal([]string{"signer-a", "signer-b", "signer-c"}, conf.Node.Signers)
}

func TestReadConfigurationReturnsParseError(t *testing.T) {
	require := require.New(t)

	path := filepath.Join(t.TempDir(), "invalid.toml")
	require.NoError(os.WriteFile(path, []byte("[api"), 0o600))

	conf, err := ReadConfiguration(path)
	require.Error(err)
	require.NotNil(conf)
}

func TestReadConfigurationReturnsFileError(t *testing.T) {
	require := require.New(t)

	conf, err := ReadConfiguration(filepath.Join(t.TempDir(), "missing.toml"))
	require.Error(err)
	require.Nil(conf)
}
