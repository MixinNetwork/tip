package tip

import "golang.org/x/crypto/argon2"

func DeriveSecret(pin, seed string) []byte {
	return argon2.IDKey([]byte(pin), []byte(seed), 1024, 256*1024, 4, 64)
}
