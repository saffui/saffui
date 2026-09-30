# eSignet 1.x, on this machine

MOSIP's Collab environment, and many a national deployment, still run eSignet
1.x. This rig runs eSignet 1.6.2 with the plugins and the mock identity system
MOSIP ships for development, so the broker can be benched against the
generation that verifies client assertions in RS256 alone. The 2.0 rig is in
`deploy/esignet`.

## Starting it

```
./fetch.sh
docker compose -p saffui-esignet-1x up -d
curl http://localhost:13000/.well-known/openid-configuration
```

`fetch.sh` takes two files from MOSIP's repository, the database seed and the
proxy in front of the sign-in page, at the commit this rig was checked
against (release-1.6.x), and refuses them if their SHA-256 differs. They land
in `upstream/`, which git ignores. Beside `postgres:17`, the four images come
from Docker Hub and take about 690 MB compressed.

| Port | Service |
|---|---|
| 13000 | eSignet's sign-in page and its proxy, the host eSignet names itself by |
| 18088 | eSignet itself |
| 18082 | the mock identity system |
| 15455 | their database |

Everything is published on the host's loopback only.

## A person and a client

The bench creates what it signs in with:

- a person, through the mock identity system's
  `POST /v1/mock-identity-system/identity`, who signs in with the one-time
  code the mock always takes, `111111`.
- a client, through `POST /v1/esignet/client-mgmt/client`, which this demo
  leaves open behind its anti-forgery token (`GET /v1/esignet/csrf/token`,
  sent back as the `XSRF-TOKEN` cookie and the `X-XSRF-TOKEN` header).

## What eSignet 1.x does that a relying party has to know

Checked against this rig on 2026-09-29, and in MOSIP's own configuration for
Collab.

- The client assertion is verified in RS256 alone, under the RSA key the
  client registered, and only when its audience is the token endpoint's
  address exactly. eSignet 2.0 takes the issuer as audience and never RS256.
  The discovery document announces RS256 alone, which is how the broker tells
  it apart and proposes an RS256 key for the provider.
- The discovery document names the host as the issuer, while the ID token
  names the host followed by `/v1/esignet`. A provider for eSignet 1.x is
  therefore given that second address as its issuer; its discovery document is
  read from the host.
- A claims request must name `id_token` beside `userinfo`, even empty, or the
  sign-in is refused as `invalid_claim`.
- The userinfo is signed RS256 by the mock identity system, under a key
  eSignet does not publish and with the issuer its `local` profile names. The
  broker cannot verify it, so a provider for eSignet 1.x reads the ID token
  alone.
- A redirect address under the reserved `.test` domain is refused at
  registration.
- The sign-in page proves each step belongs to the transaction it opened with
  the SHA-256 of that transaction's details as eSignet wrote them.

## Benching the broker against it

With the rig up and the test database the other suites use:

```
SAFFUI_TEST_PG="host=localhost port=55455 user=postgres password=saffui dbname=saffui" \
SAFFUI_TEST_ESIGNET_1X=http://localhost:13000 \
cargo test -p server --test suite_federation -- --include-ignored --test-threads=1 esignet_1x
```

Each journey reads eSignet's discovery document through the admin plane,
plants its own person and registers its own client with the public key the
provider drew, then walks eSignet's sign-in the way its page does. The mock
identity system is reached at `http://localhost:18082/v1/mock-identity-system`
unless `SAFFUI_TEST_ESIGNET_1X_IDENTITY` names another address. Without
`SAFFUI_TEST_ESIGNET_1X`, the journeys are skipped.

## Stopping it

```
docker compose -p saffui-esignet-1x down -v
```

`-v` drops the database with the people and clients the bench created.
