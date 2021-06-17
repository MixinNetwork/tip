package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/MixinNetwork/tip/config"
	"github.com/MixinNetwork/tip/messenger"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
	"github.com/btcsuite/btcutil/base58"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/util/random"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:                 "tip",
		Usage:                "TIP (Throttled Identity PIN) is a decentralized key custodian.",
		Version:              "0.0.1",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:   "node",
				Usage:  "Run the signer node",
				Action: runNode,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "config",
						Aliases: []string{"c"},
						Value:   "~/.tip/config.toml",
						Usage:   "configuration file path",
					},
				},
			},
			{
				Name:   "key",
				Usage:  "Generate a key pair",
				Action: genKey,
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func runNode(c *cli.Context) error {
	ctx := context.Background()

	cp := c.String("config")
	if strings.HasPrefix(cp, "~/") {
		usr, _ := user.Current()
		cp = filepath.Join(usr.HomeDir, (cp)[2:])
	}

	conf, err := config.ReadConfiguration(cp)
	if err != nil {
		return err
	}

	store, err := store.OpenBadger(ctx, conf.Store)
	if err != nil {
		return err
	}

	messenger, err := messenger.NewMixinMessenger(ctx, conf.Messenger)
	if err != nil {
		panic(err)
	}

	node := signer.NewNode(ctx, store, messenger, conf.Node)
	return node.Run(ctx)
}

func genKey(c *cli.Context) error {
	suite := bn256.NewSuiteG2()
	scalar := suite.Scalar().Pick(random.New())
	point := suite.Point().Mul(scalar, nil)

	msg := []byte("tip")
	scheme := bls.NewSchemeOnG1(suite)
	sig, err := scheme.Sign(scalar, msg)
	if err != nil {
		return err
	}
	err = scheme.Verify(point, msg, sig)
	if err != nil {
		return err
	}

	b, err := point.MarshalBinary()
	if err != nil {
		return err
	}
	pub := base58.CheckEncode(b, signer.KeyVersion)
	fmt.Println(scalar)
	fmt.Println(pub, err)
	return nil
}
