package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

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
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Value:   "~/.tip/config.toml",
				Usage:   "Configuration file path",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "node",
				Usage:  "Run the signer node",
				Action: runNode,
			},
			{
				Name:   "setup",
				Usage:  "Request a DKG setup",
				Action: requestSetup,
				Flags: []cli.Flag{
					&cli.Uint64Flag{
						Name:  "nonce",
						Usage: "The nonce should match all other nodes",
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

func requestSetup(c *cli.Context) error {
	ctx := context.Background()

	nonce := c.Uint64("nonce")
	if nonce < 1024 {
		return fmt.Errorf("nonce too small")
	}

	cp := c.String("config")
	conf, err := config.ReadConfiguration(cp)
	if err != nil {
		return err
	}

	key, err := signer.PrivateKeyFromHex(conf.Node.Key)
	if err != nil {
		panic(conf.Node.Key)
	}

	messenger, err := messenger.NewMixinMessenger(ctx, conf.Messenger)
	if err != nil {
		panic(err)
	}

	msg := signer.MakeSetupMessage(ctx, key, nonce)
	data := base64.RawURLEncoding.EncodeToString(msg)
	fmt.Println(data, len(msg))
	return messenger.SendMessage(ctx, msg)
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
