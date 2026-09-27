# eSignet, on this machine

MOSIP eSignet is how a national identity built on MOSIP signs people in to
other services: plain OpenID Connect in front of the national register. This
rig runs eSignet 2.0.0 with the mock identity system MOSIP ships for
development, so the broker can be benched against the real thing and tried by
hand.

## Starting it

```
./fetch.sh
docker compose -p saffui-esignet up -d
curl http://localhost:18080/.well-known/openid-configuration
```

`fetch.sh` takes two files from MOSIP's repository, the database seed and the
proxy in front of the sign-in page, at the commit this rig was checked
against, and refuses them if their SHA-256 differs. They land in `upstream/`,
which git ignores. The four images come from Docker Hub and take about 1.1 GB.

| Port | Service |
|---|---|
| 18080 | eSignet, issuer `http://localhost:18080` |
| 3000 | eSignet's sign-in page |
| 8082 | the mock identity system |
| 5455 | their database |

Everything is published on the host's loopback only.

## A person and a client

The seed plants no client and one person this bench does not use. The bench
creates what it signs in with:

- a person, through the mock identity system's
  `POST /v1/mock-identity-system/identity`. The knowledge-based sign-in asks
  for their individual ID, full name and date of birth.
- a client, through `POST /client-mgmt/client`, which this demo leaves open.
  A real deployment registers clients through its partner management, with
  the public keys the broker's provider shows in the console.

## What eSignet 2.0.0 does that a relying party has to know

Checked against this rig on 2026-09-27.

- The client assertion must name the issuer as its audience and carry a `kid`
  in its header. The token endpoint's address as audience, or a header
  without `kid`, is refused as an invalid client. It is taken signed PS256,
  ES256, ES256K or EdDSA, never RS256.
- The ID token is signed PS256. The userinfo is signed RS256, with a key the
  published key set labels PS256 (upstream issue #2533), and the discovery
  document announces PS256 for it too. Reading a provider from its issuer
  therefore leaves the userinfo algorithms as they were set.
- Encrypted, the userinfo is a JWE with `RSA-OAEP-256` and `A256GCM`, carrying
  the signed userinfo inside (`cty: JWT`).
- The userinfo is signed by the mock identity system, under its own issuer
  setting. Its `local` profile names an older address; `compose.yaml` sets it
  to eSignet's issuer.
- A birth date comes as `YYYY/MM/DD`.
- The `sub` is pairwise per relying party, not per client.

## Benching the broker against it

With the rig up and the test database the other suites use:

```
SAFFUI_TEST_PG="host=localhost port=55455 user=postgres password=saffui dbname=saffui" \
SAFFUI_TEST_ESIGNET=http://localhost:18080 \
cargo test -p server --test suite_federation -- --include-ignored --test-threads=1 esignet
```

Each journey reads eSignet's discovery document through the admin plane for
the provider's endpoints, plants its own person and registers its own client,
with the public keys the provider drew, then walks eSignet's sign-in the way
its page does. The way back is required to name its issuer, which eSignet
announces. The mock identity system is reached at
`http://localhost:8082/v1/mock-identity-system` unless
`SAFFUI_TEST_ESIGNET_IDENTITY` names another address. Without
`SAFFUI_TEST_ESIGNET`, the journeys are skipped.

Walking the sign-in by hand through its API, the consent answer carries an
approval of its own beside each purpose's and each claim's; without it, eSignet
denies every claim.

## Stopping it

```
docker compose -p saffui-esignet down -v
```

`-v` drops the database with the people and clients the bench created.
