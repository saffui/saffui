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
  without `kid`, is refused as an invalid client.
- The ID token is signed PS256. The userinfo is signed RS256, with a key the
  published key set labels PS256 (upstream issue #2533).
- Encrypted, the userinfo is a JWE with `RSA-OAEP-256` and `A256GCM`, carrying
  the signed userinfo inside (`cty: JWT`).
- The userinfo is signed by the mock identity system, under its own issuer
  setting. Its `local` profile names an older address; `compose.yaml` sets it
  to eSignet's issuer.
- A birth date comes as `YYYY/MM/DD`.
- The `sub` is pairwise per relying party, not per client.

## Stopping it

```
docker compose -p saffui-esignet down -v
```

`-v` drops the database with the people and clients the bench created.
