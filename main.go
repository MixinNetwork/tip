package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/MixinNetwork/tip/api"
	"github.com/MixinNetwork/tip/config"
	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/crypto/en256"
	"github.com/MixinNetwork/tip/messenger"
	tip "github.com/MixinNetwork/tip/sdk/go"
	"github.com/MixinNetwork/tip/signer"
	"github.com/MixinNetwork/tip/store"
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
				Name:   "signer",
				Usage:  "Run the signer node",
				Action: runSigner,
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
			{
				Name:   "api",
				Usage:  "Run the api node",
				Action: runAPI,
			},
			{
				Name:   "sign",
				Usage:  "Request a signature",
				Action: requestSign,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "config",
						Usage: "The signers configuration",
					},
					&cli.StringFlag{
						Name:  "key",
						Usage: "The identity key",
					},
					&cli.StringFlag{
						Name:  "ephemeral",
						Usage: "The ephemeral seed",
					},
					&cli.StringFlag{
						Name:  "rotate",
						Usage: "The ephemeral rotation",
					},
					&cli.StringFlag{
						Name:  "assignee",
						Usage: "The identity assignee",
					},
					&cli.Int64Flag{
						Name:  "nonce",
						Usage: "The nonce",
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}

func runSigner(c *cli.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	node := signer.NewNode(ctx, cancel, store, messenger, conf.Node)
	return node.Run(ctx)
}

func runAPI(c *cli.Context) error {
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

	node := signer.NewNode(ctx, nil, store, nil, conf.Node)

	ac := conf.API
	ac.Key = node.GetKey()
	ac.Signers = node.GetSigners()
	ac.Poly = node.GetPoly()
	ac.Share = node.GetShare()
	server := api.NewServer(store, ac)
	return server.ListenAndServe()
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

	key, err := crypto.PrivateKeyFromHex(conf.Node.Key)
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
	suite := en256.NewSuiteG2()
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

	pub := crypto.PublicKeyString(point)
	fmt.Println(scalar)
	fmt.Println(pub, err)
	return nil
}

func requestSign(c *cli.Context) error {
	f, err := os.ReadFile(c.String("config"))
	if err != nil {
		return err
	}
	conf, err := tip.LoadConfigurationJSON(string(f))
	if err != nil {
		return err
	}
	client, _, err := tip.NewClient(conf)
	if err != nil {
		return err
	}
	grace := int64(time.Hour * 24 * 128)
	key := c.String("key")
	ephemeral := c.String("ephemeral")
	nonce := c.Int64("nonce")
	rotate := c.String("rotate")
	assignee := c.String("assignee")
	sig, evicted, err := client.Sign(key, ephemeral, nonce, grace, rotate, assignee)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(sig))
	for _, sp := range evicted {
		fmt.Println(sp.Identity, sp.API)
	}
	return nil
}
