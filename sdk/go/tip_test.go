package tip

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/MixinNetwork/tip/api"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
)

func TestTip(t *testing.T) {
	// assert := assert.New(t)
	testRunServer(7025)
}

func testRunServer(port int) error {
	ctx := context.Background()
	store := testBadgerStore(port)
	if store == nil {
		panic(errors.New("store is nil"))
	}
	conf := testTipNode(port)
	if conf == nil {
		panic(errors.New("conf is nil"))
	}
	node := signer.NewNode(ctx, nil, store, nil, conf)
	ac := &api.Configuration{
		Port: port,
	}
	ac.Key = node.GetKey()
	ac.Signers = node.GetSigners()
	ac.Poly = node.GetPoly()
	ac.Share = node.GetShare()
	server := api.NewServer(store, ac)
	return server.ListenAndServe()
}

func testBadgerStore(port int) *store.BadgerStorage {
	path := fmt.Sprintf("tip%d", port)
	var share string
	switch port {
	case 7021:
		share = "000000028f36089865a5b1f36ed65ec8a6caa0082455a83b8469ed5c167f2700a0bb1264"
	case 7022:
		share = "00000000263e3d0c7a942e18a2206a791298346271a0a51eefc9178dc2d3714dec5e9469"
	case 7023:
		share = "00000001376ef740e9f5a867129d54a811dd256272fe46359dfe0680c27d327f8d02576b"
	case 7024:
		share = "000000030e296d4c585d3aca61ebaf6a0e56ec11288baf0ab2b659d78a7b661a782fe092"
	}
	if share == "" {
		return nil
	}

	dir, err := os.MkdirTemp("/tmp", path)
	if err != nil {
		panic(err)
	}
	conf := &store.BadgerConfiguration{
		Dir: dir,
	}
	bs, err := store.OpenBadger(context.Background(), conf)
	if err != nil {
		panic(err)
	}
	shareBuf, _ := hex.DecodeString(share)
	publicBuf, _ := hex.DecodeString(polyPublic)
	err = bs.WritePoly(publicBuf, shareBuf)
	if err != nil {
		panic(err)
	}
	return bs
}

func testTipNode(port int) *signer.Configuration {
	key := ""
	switch port {
	case 7021:
		key = "2d3ef9158573d306210ad2579e78e2e99177542d8b1831c3828a40a556d66f35"
	case 7022:
		key = "6869e481b5ede57ec00504e1b76682aa62980cb0e46a3d9031bdb50acf8cb1c5"
	case 7023:
		key = "83f3daf28a106d20fb3a5dfa2a6f2822c76fccf7e88f16e9a31acb6d3f73c2c0"
	case 7024:
		key = "1d86753d770a1ced1103edb2ffd11728ee4ab6aed41094732c1748c72f2e181d"
	}
	if key == "" {
		return nil
	}
	return &signer.Configuration{
		Key:     key,
		Signers: signers,
	}
}

var signers = []string{
	"5JRrcBgsnUVr8D7tdTHX8nZAbkpPD4C5TS82KEbBMiV3inVp1vSu4gBwB1WwhQFguGbmkgrvA2vmtfY6GXhyFnh4SRoEQT2jVNTsk91pcPUaZ8nQcEdDAUjKXCTFi6TPDYPYPUsAK67kUXEtyNocsYUijKdF9pGRKUk92Rk7iRuJ3eqADYH7NB",
	"5HrRVnj6PdfxKojB44te1XqhDSCexUxSognLi96SVx5B6VdnKkbyvUGcpkdQodg9rKgxM5v61ypmbJNGVWJTuacKUSZQfkq1mnc6P4XybemuXYmwSd5g2zkaArPc8VDTU5eEPuvgguSD8cnEgnMZzW7rJfaWoJU1DW6k2ujzUx15EjAG3WDTeG",
	"5HzufHDbh8kUj3oBiYWeEe4wamNMmQ4BZ5uZULxGsyKYULpWLUdzzBb73EExRDgUxZD5vu6iA61ds7QGSjeCWazSmpXv7sMaHfizSnHjxeoEy1TumWVqGJhtAAYwAJPzUbTdyzEGz5r9hRSYFAmHkhwCwLi8BoSk8V2scv6r7LdfphGbXSWSAV",
	"5Jt4ztqknKHcAw13RALYx2mXT9qkKKJTvrU7W7HNcF7vGKxzh5tvSqQvrY4aZCVqzk46DV8X69qudryZsjyKjzLJMjyRMYiDoQY7WZvNk874cibXAoZrUbp7Eyc8DgNLnPycisLbNofh3iJpKMK2qpsQH7AsFkAMdhH8KLFoBGruTs1XcevoC1",
}

const (
	polyPublic = "596e6b811ba03ae0e2b3db8ae6f10ef5fb5493a2379751608b6a2e119def22af82dc26c672c5571631fc00f1943be08780d81272de4bf0ec8dfc3d9f37df7e3d1ec070e432c22789b742b16a5b551cf0148ef2ed32b85641a97b0da94035e67c06511a95ce015d750a16299a8ec4822603d0c91ad79a90ce865b7141f07729bd724e1b2e4cd7d550b80340d1dde642fed186774aed35941fd6a8e83950d3c1973090596cdc586297270210ec3d42c438e6e8c2894ac7eec297b4ad9a193494e130f47ebadbc7259c69deea91fc9a153e18304e209e8105932800e6f74ab75d78734fb8428da5735e45ab6bdc29e1816c33eb344ac8e679ab16e0af5e6c4b323d8195bc8edd1c0d2e078f5f5a0953163b87e1469213605e5af374309e197a0917753f944543beb8e7c6454d2d83fbac4f32d40386b3881548833297219f39a7b843678d1544b3c12f33535e4cfb81199488a8255c2547fe83e3b31adcd6172f858824132349a082d4db81e75747e82e3684e7c7965ff44d01ef48ca310ade5d6d"
)
