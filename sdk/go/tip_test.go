package tip

import (
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/stretchr/testify/assert"
)

func TestTip(t *testing.T) {
	assert := assert.New(t)
	bs := testBadgerStore("tip7021")
	share, _ := hex.DecodeString(polyShare)
	public, _ := hex.DecodeString(polyPublic)
	err := bs.WritePoly(public, share)
	assert.Nil(err)
	shareBuf, err := bs.ReadPolyShare()
	assert.Nil(err)
	assert.Equal(polyShare, hex.EncodeToString(shareBuf))
	publicBuf, err := bs.ReadPolyPublic()
	assert.Nil(err)
	assert.Equal(polyPublic, hex.EncodeToString(publicBuf))
}

func testBadgerStore(path string) *store.BadgerStorage {
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
	return bs
}

func testTipNode1() *signer.Configuration {
	return &signer.Configuration{
		Key:     "2d3ef9158573d306210ad2579e78e2e99177542d8b1831c3828a40a556d66f35",
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
	polyShare  = "000000028f36089865a5b1f36ed65ec8a6caa0082455a83b8469ed5c167f2700a0bb1264"
	polyPublic = "596e6b811ba03ae0e2b3db8ae6f10ef5fb5493a2379751608b6a2e119def22af82dc26c672c5571631fc00f1943be08780d81272de4bf0ec8dfc3d9f37df7e3d1ec070e432c22789b742b16a5b551cf0148ef2ed32b85641a97b0da94035e67c06511a95ce015d750a16299a8ec4822603d0c91ad79a90ce865b7141f07729bd724e1b2e4cd7d550b80340d1dde642fed186774aed35941fd6a8e83950d3c1973090596cdc586297270210ec3d42c438e6e8c2894ac7eec297b4ad9a193494e130f47ebadbc7259c69deea91fc9a153e18304e209e8105932800e6f74ab75d78734fb8428da5735e45ab6bdc29e1816c33eb344ac8e679ab16e0af5e6c4b323d8195bc8edd1c0d2e078f5f5a0953163b87e1469213605e5af374309e197a0917753f944543beb8e7c6454d2d83fbac4f32d40386b3881548833297219f39a7b843678d1544b3c12f33535e4cfb81199488a8255c2547fe83e3b31adcd6172f858824132349a082d4db81e75747e82e3684e7c7965ff44d01ef48ca310ade5d6d"
)
