package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

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
