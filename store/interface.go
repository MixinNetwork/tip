package store

import "time"

type Storage interface {
	ReadPolyPublic() ([]byte, error)
	ReadPolyShare() ([]byte, error)
	WritePoly(public, share []byte) error

	CheckLimit(key []byte, duration time.Duration, limit uint32) (int, error)
	CheckNonce(key, nonce []byte, duration time.Duration) (bool, error)
}
