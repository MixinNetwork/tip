package store

import "time"

type Storage interface {
	CheckPolyGroup(group []byte) (bool, error)
	ReadPolyPublic() ([]byte, error)
	ReadPolyShare() ([]byte, error)
	WritePoly(public, share []byte) error

	WriteAssignee(key []byte, assignee []byte) error
	ReadAssignor(key []byte) ([]byte, error)
	ReadAssignee(key []byte) ([]byte, error)
	CheckLimit(key []byte, window time.Duration, quota uint32, increase bool) (int, error)
	CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error)
	RotateEphemeralNonce(key, ephemeral []byte, nonce uint64) error
	WriteSignRequest(key, watcher []byte) (time.Time, int, error)
	Watch(key []byte) (time.Time, int, error)
}
