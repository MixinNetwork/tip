package store

import "time"

type Storage interface {
	ReadPolyPublic() ([]byte, error)
	ReadPolyShare() ([]byte, error)
	WritePoly(public, share []byte) error

	CheckLimit(key []byte, window time.Duration, quota uint32, increase bool) (int, error)
	CheckEphemeralNonce(key, ephemeral []byte, nonce uint64, grace time.Duration) (bool, error)
	RotateEphemeralNonce(key, ephemeral []byte, nonce uint64) error
}
