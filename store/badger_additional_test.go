package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBadgerPolyStorageRotateAndWatchMissing(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	pub, err := bs.ReadPolyPublic()
	require.NoError(err)
	require.Nil(pub)

	share, err := bs.ReadPolyShare()
	require.NoError(err)
	require.Nil(share)

	err = bs.WritePoly([]byte("public"), []byte("share"))
	require.NoError(err)

	pub, err = bs.ReadPolyPublic()
	require.NoError(err)
	require.Equal([]byte("public"), pub)

	share, err = bs.ReadPolyShare()
	require.NoError(err)
	require.Equal([]byte("share"), share)

	assignor, genesis, counter, err := bs.Watch([]byte("missing"))
	require.NoError(err)
	require.Nil(assignor)
	require.True(genesis.IsZero())
	require.Equal(0, counter)

	err = bs.RotateEphemeralNonce([]byte("assignor"), []byte("ephemeral"), 7)
	require.NoError(err)

	valid, err := bs.CheckEphemeralNonce([]byte("assignor"), []byte("ephemeral"), 7, time.Hour)
	require.NoError(err)
	require.False(valid)

	valid, err = bs.CheckEphemeralNonce([]byte("assignor"), []byte("ephemeral"), 8, time.Hour)
	require.NoError(err)
	require.True(valid)
}

func TestBadgerWriteSignRequestValidationAndConflict(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	_, _, err := bs.WriteSignRequest(nil, []byte("watcher"))
	require.Error(err)

	_, _, err = bs.WriteSignRequest([]byte("assignor"), nil)
	require.Error(err)

	_, _, err = bs.WriteSignRequest([]byte("assignor-1"), []byte("watcher"))
	require.NoError(err)

	_, _, err = bs.WriteSignRequest([]byte("assignor-2"), []byte("watcher"))
	require.Error(err)
	require.Contains(err.Error(), "invalid watcher")
}

func TestBadgerWriteAssigneeRejectsExistingAssignee(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	err := bs.WriteAssignee([]byte("key-2"), []byte("key-3"))
	require.NoError(err)

	err = bs.WriteAssignee([]byte("key-1"), []byte("key-2"))
	require.Error(err)
	require.Contains(err.Error(), "invalid assignee as is assignee")

	err = bs.WriteAssignee([]byte("key-4"), []byte("key-3"))
	require.Error(err)
	require.Contains(err.Error(), "invalid assignor as is assignee")
}

func TestOpenBadgerInvalidPathAndClosePanic(t *testing.T) {
	require := require.New(t)

	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	require.NoError(os.WriteFile(file, []byte("x"), 0o600))

	_, err := OpenBadger(context.Background(), &BadgerConfiguration{Dir: file})
	require.Error(err)

	closeDir := filepath.Join(t.TempDir(), "badger-close")
	bs, err := OpenBadger(context.Background(), &BadgerConfiguration{Dir: closeDir})
	require.NoError(err)

	moved := closeDir + "-moved"
	require.NoError(os.Rename(closeDir, moved))
	require.Panics(func() {
		bs.Close()
	})
}

func TestBadgerClosedDBErrors(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	bs.Close()

	valid, err := bs.CheckPolyGroup([]byte("group"))
	require.Error(err)
	require.False(valid)

	_, err = bs.ReadPolyPublic()
	require.Error(err)
	_, err = bs.ReadPolyShare()
	require.Error(err)
	err = bs.WritePoly([]byte("public"), []byte("share"))
	require.Error(err)

	_, err = bs.ReadAssignee([]byte("assignor"))
	require.Error(err)
	_, err = bs.ReadAssignor([]byte("assignor"))
	require.Error(err)

	_, _, _, err = bs.Watch([]byte("watcher"))
	require.Error(err)
	_, _, err = bs.WriteSignRequest([]byte("assignor"), []byte("watcher"))
	require.Error(err)

	_, err = bs.CheckLimit([]byte("limit"), time.Hour, 1, true)
	require.Error(err)
	_, err = bs.CheckEphemeralNonce([]byte("assignor"), []byte("ephemeral"), 1, time.Hour)
	require.Error(err)
	err = bs.RotateEphemeralNonce([]byte("assignor"), []byte("ephemeral"), 1)
	require.Error(err)
	err = bs.WriteAssignee([]byte("assignor"), []byte("assignee"))
	require.Error(err)
}

func TestBadgerWriteSignRequestWithExistingCounterAndNewWatcher(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	assignor := []byte("assignor")
	require.NoError(bs.WriteAssignee(assignor, assignor))

	genesis, counter, err := bs.WriteSignRequest(assignor, []byte("watcher-1"))
	require.NoError(err)
	require.Equal(1, counter)

	nextGenesis, nextCounter, err := bs.WriteSignRequest(assignor, []byte("watcher-2"))
	require.NoError(err)
	require.True(genesis.Equal(nextGenesis))
	require.Equal(counter, nextCounter)

	gotAssignor, gotGenesis, gotCounter, err := bs.Watch([]byte("watcher-2"))
	require.NoError(err)
	require.Equal(assignor, gotAssignor)
	require.True(genesis.Equal(gotGenesis))
	require.Equal(counter, gotCounter)
}

func TestBadgerRejectsOversizedKeys(t *testing.T) {
	require := require.New(t)
	bs := testBadgerStore()
	defer bs.Close()

	huge := bytes.Repeat([]byte("k"), 70000)

	err := bs.WriteAssignee(huge, []byte("assignee"))
	require.Error(err)

	err = bs.WriteAssignee([]byte("assignor"), huge)
	require.Error(err)

	_, _, err = bs.WriteSignRequest(huge, []byte("watcher"))
	require.Error(err)

	_, _, err = bs.WriteSignRequest([]byte("assignor"), huge)
	require.Error(err)
}
