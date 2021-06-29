# Signer Node

The signer runs a [threshold Boneh-Lynn-Shacham (BLS) signatures](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham) DKG, which generates a collective public key and a secret share for each node respectively. For *n* total signers, the threshold *t = n * 2 / 3 + 1*.

Each signer node runs independently and doesn't have direct network connection with other nodes. They broadcast messages to a Mixin Messenger group chat which includes all the signers to exchange key generation information.

## Setup Key

After all entities have reach a consensus, each entity should prepare a signer key and then forms a list of signer keys. To generate a key pair, run the command:

```
$ tip key
2bd462c1f02fa96234...3b6560fe308d5c6e74
5JhLbaTYCXbqFxibfX19GW...cTBg1UDpQ9xfMxXxtnzQS1
```

Then put the private key to `[node].key` section of **config/example.toml**, and share the public key with all other entities. After all entities make their public keys exchanged, they should sort the keys list in the same order and put them to `[node].signers`.

## Setup Messenger

Go to the Mixin Messenger [developers dashboard](https://developers.mixin.one/dashboard) and create a bot for the signer, then in the secret section generate an Ed25519 session. Edit **config/example.toml**, and put `client_id` to `[messenger].user`, `session_id` to `[messenger].session`, and `private_key` to `[messenger].key`.

Then all the entities should add all their bots to a Mixin Messenger group chat, then send the link `https://mixin.one/context` to the group chat and open it to  obtain a UUID, which is the `[messenger].conversation` value.

## Run Signer DKG

Change `[store].dir` to a secure and permanent directory, this is where the signer database resides. Then the **config/example.toml** is finished, put it to a proper path, e.g. ~/.tip/config.toml.

```
$ tip -c ~/.tip/config.toml signer
```

All entities should run the command above to prepare for the DKG process, and after all entities have started the node, all of them should run the command below.

```
$ tip -c ~/.tip/config.toml setup -nonce 887378
```

This command sends out the DKG setup signal to the Mixin Messenger group chat, and after enough signals received, the DKG starts. The `nonce` value must be a large number and all entities should use the same one.

If the DKG finishes successfully, the node will exit with the output similar to below message.

```
runDKG 5cc8735afb....b34b4 000000035...f43fd402
```

The first and long hex is the commitments for the collective public key, and all entities should share it with others to ensure their nodes produce identical public key. The second and short hex is the private share, which should not be shared to anyone else, and must have a secure backup.

If some node fails to produce the same public key, all the entities should remove the failed database and restart the DKG setup process until success.

## Run Signer API

After the DKG process successfully, all nodes should start the signer API to accept signing requests from users.

```
$ tip -c ~/.tip/config.toml api
```

It's highly recommended to make a firewall and reverse proxy to hide the actual API server from public.
