# What the hot paths cost, on one machine

```
docker build -t saffui:local .           # the rig never builds it for you
node deploy/load/harness.mjs             # add --keep to look around
node deploy/load/harness.mjs --seconds=20 --workers=32
```

One saffui, one Postgres, and a person the rig provisions. The harness drives three paths at a fixed number of workers for
a fixed number of seconds and prints, for each, how many answers came back,
how many refused, and where the latencies land.

## The three paths

- **A whole sign-in.** The authorization endpoint opens it, the password is
  answered, and the code is exchanged: the heaviest path a person walks.
- **Discovery.** The realm's `openid-configuration`: the cheapest read the
  plane serves, and the floor the other numbers are read against.
- **A person's claims.** `userinfo` under a token from a whole code flow,
  which touches the session behind the token.

## What these numbers are, and are not

They are the shape of three paths on the machine that ran them, with a
database in a container beside the server and the harness on the same host.
They are not a deployment's capacity: no network sits between the parts, one
instance answers, and the database holds a handful of rows. Read them to see
what a change did to a path, by running the same rig before and after, and
never as a number to put in front of anyone.

The server's own count is printed beside the harness's: the operations port
serves `/metrics`, and the harness reads the request counter before and
after, so the two views can be compared. The plane always counts more, and
by a knowable amount: one sign-in is three requests to it, the authorization
endpoint, the password answer and the exchange, where the harness counts one
answer. The readiness probes and the warmups are in its count too. A gap
wider than that is worth more attention than either number alone.
