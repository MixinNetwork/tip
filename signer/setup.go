package signer

func (node *Node) Setup() error {
	priv, err := node.store.ReadPolyShare()
	if err != nil || priv != nil {
		return err
	}
	pub, err := node.store.ReadPolyPublic()
	if err != nil || pub != nil {
		return err
	}

	pub, priv, err = node.runDKG()
	if err != nil {
		return err
	}
	return node.store.WritePoly(pub, priv)
}

func (node *Node) runDKG() ([]byte, []byte, error) {
	return nil, nil, nil
}
