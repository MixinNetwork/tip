package store

type Storage interface {
	ReadPolyPublic() ([]byte, error)
	ReadPolyShare() ([]byte, error)
	WritePoly(public, share []byte) error
}
