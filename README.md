# Throttled Identity Protocol

Throttled Identity Protocol (TIP) is a decentralized key derivation protocol, which allows people to obtain a strong secret key through a very simple passphrase, e.g. a six-digit PIN.

## Mission and Overview

Along with the rising of Bitcoin and other cryptocurrencies, the saying "not your keys, not your coins" has become well-known. That's true, very true and definitely true, that's the right and freedom Bitcoin has given people. Whoever can access the key can move the money, and nobody without the key is able to do that.

That said it's better to manage your own Bitcoin private key than let your coins lie in some centralized exchanges. However, it's admitted that key management requires superior skills, which most people lack. And the result is people who own their keys lose the coins permanently due to various accidents, and those who opened a Coinbase account years ago can still get back their assets easily.

The embarrassing result doesn't prove the security of centralized exchanges, yet exposes the drawbacks of key management. The key grants people the right to truly own their properties, but people lose money due to poor key management skills. People should not be blamed for that, it's the problem of the key itself.

Bitcoin gives people the right and freedom to own their properties, and people deserve the convenience to manage their keys. Current private key or mnemonic phrase designs are over-complicated for people to keep properly. Instead of fearing the corruption of centralized financial institutions, people become slaves of the private key.

It's what TIP strives to do. Let people truly own their coins with a six-digit PIN. This decentralized PIN is easy to remember for any person, doesn't require any special skills or hardware, and people can manage their coins with more confidence than ever.

## Protocol Design

TIP involves three independent parties to make the protocol work. A decentralized signer network authenticates signing requests from the user, and throttles malicious attempts; A trusted account manager serves the user an identity seed, which typically authenticates the user by email or phone verification code; The user remembers a PIN and combines the identity seed from the account manager, then makes independent requests to enough signer network nodes, and finally derives their secret key.

### Decentralized Network Setup

The decentralized signer network is launched cooperatively by many different entities. Specifically, those entities gather and reach a consensus to run some node software, those nodes interactively run a distributed key generation protocol. For TIP, the DKG is [threshold Boneh-Lynn-Shacham (BLS) signatures](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham).

Assuming *n* entities agree to launch the network, they generate an asymmetric key pair respectively and configure their node software to include all the entities' public keys in a deterministic order. Then they boot the nodes to run a *t*-of-*n* (where _t = n * 2 / 3 + 1_) DKG protocol to set up a collective public key *P* and private key shares *s<sub>i</sub>* respectively.

After the DKG protocol finishes, all entities should share the public key *P* to ensure they hold the same one, keep their private key shares *s<sub>i</sub>* cautiously, and should make professional backups.

Finally, all entities should boot their node software to accept throttled signing requests from users. And again, they should safeguard the node servers and defend against all malicious attacks.

This repository includes an implementation of the signer node software, for instructions please see the **signer** directory.

### Throttled Secret Derivation

The network announces the configuration and signers list to the public or potential users and waits for signing requests. Each signer should throttle the requests based on the same restrictions.

- **Identity.** This is the base factor for all restrictions, the identity should be a valid BLS public key, and a user should use the same identity for all signers. The signer checks the request and verifies the request signature against the public key, and the signer must reduce the request quota of this identity for any invalid signature.
- **Ephemeral.** This parameter is a different random value for each signer but should remain unchanged for the same signer during the ephemeral grace period. If the ephemeral changes during the grace period, the signer must reduce the ephemeral requests quota of this identity.
- **Nonce.** For each signing request, the user should increase the nonce during the ephemeral grace period. If the nonce is invalid during the grace period, the signer must reduce the ephemeral requests quota of this identity.

After the signing request passes all throttle checks, the signer responds back a part of the *t*-of-*n* threshold BLS signature by signing the identity. Whenever the user collects *t* valid partials, they can recover the final collective signature and verify it with the collective public key.

The final collective signature is the seed to the secret key of the user. Then it's up to the user to use different algorithms to generate their private key for Bitcoin or other usages. It doesn't need any further requests to use this secret key, and in case of a loss, the user can recover it by making the same requests.

For details of the throttle restrictions, please see the **keeper** directory.

### Threshold Identity Generation

The mission of TIP network is to let people truly own their coins by only remembering a 6-digit PIN, so they should not have the duty to store *identity*, *ephemeral* or *nonce*. They are capable of achieving this goal through the threshold identity generation process with the help from the trusted account manager.

1. User authenticates themself with a trusted account manager through email or phone verification code, and the manager responds with the identity seed *S<sub>i</sub>*.
2. User chooses a very slow hash function *H<sub>s</sub>*, e.g. argon2id, and generates the identity *I = H<sub>s</sub>(PIN || S<sub>i</sub>)*.
3. User generates a random ephemeral seed *S<sub>e</sub>*, and stores the seed on its device securely.
4. For each signer *i* in the network with public key *P<sub>i</sub>*, user generates the ephemeral *e<sub>i</sub> = H<sub>s</sub>(I || S<sub>e</sub> || P<sub>i</sub>)*.
5. User sends signing requests *(I, e<sub>i</sub>, nonce, grace)* to each signer *i* and gathers enough partial signatures, then recover the final collective signature.
6. User must repeat the process every a while to refresh the ephemeral grace period.

The identity seed should prohibit all impersonation, the on-device random ephemeral seed should prevent the account manager collude with some signer, and the ephemeral grace period allows the user to recover its secret key when the device is lost.

Furthermore, the user can make their threshold identity generation more secure by cooperating with another user to combine their identity to increase the entropy especially when the account manager manages lots of identities.

And finally, the user can just back up his seeds like any traditional key management process, and this backup is considered more secure against loss or theft.

## Network Evolution

Once the decentralized signer network is launched, its signers should remain constant, no new entity is permitted to join the signers or replace an old signer because the DKG protocol remains valid only when all shares remain unchanged. But people need the network to become stronger, and that requires more entities to join the network. So TIP allows network evolution.

Whenever a new entity is accepted to the network, either replacing an old signer or joining as a new one, an evolution happens. Indeed, an evolution starts a fresh DKG protocol in the same process as the previous evolution, but with different signers, thus resulting in absolutely different shares for each signer. It's noted that an entity leaving the network doesn't result in any evolution, because the remaining shares can still serve requests.

In a new evolution, all signers should reference the number and the hash of the signer list from the previous evolution. After a new evolution starts, the previous evolution still works. For each signer in the new evolution, if it is a signer of the previous evolution, it must maintain its availability to serve signing requests to the previous evolution, otherwise it should be punished.

Any user requests for the throttled secret derivation should include the evolution number to get the correct signature. And in any case of network changes, the user is assured of their key security due to various backups discussed in previous sections.

## Incentive and Punishment

The code doesn't include any incentive or punishment for the entities running the signer node software. It's up to their consensus on their mission, either to serve their customers a better user experience, or charge a small key signing request fee, or they could make some tokens to do community development.

## Security

All the cryptography libraries used in this repository are being developed and used by industry-leading institutions, notably the [drand project](https://github.com/drand/drand) and its league of entropy that includes Cloudflare, EPFL, Kudelski Security, Protocol Labs, Celo, UCL, and UIUC.

The code has been audited by Certik, and the audit report can be found at https://github.com/MixinNetwork/audits.

## Contribution

The project doesn't accept feature requests and welcomes all security improvement contributions. Shall you find any security issues, please email security@mixin.one before any public disclosures or pull requests.

The core team highly values the contributions and provides at most a $100K bounty for any vulnerability report according to the severity.

## License

The TIP project is licensed under Apache 2.0 terms.
