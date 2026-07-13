# menhera-ddns

`menhera-ddns` is a small HTTP-to-DNS dynamic update service. It lets a client
reserve one hostname, receive a bearer token, and later update or delete that
hostname without giving the client a DNS update key.

The service is authoritative-server agnostic. It communicates using standard
DNS queries, RFC 2136 Dynamic Update, and HMAC-SHA256 TSIG authentication.

## How it works

For a configured zone such as `ddns.example.net.`, creating the hostname
`laptop` stores:

```text
laptop.ddns.example.net.                    TXT  "ddns=1"
<credential-hash>._token.ddns.example.net. PTR  laptop.ddns.example.net.
```

The returned token is a random 128-bit value encoded as 32 hexadecimal
characters. It is never stored in DNS. The credential owner name is derived as:

```text
base32hex(HMAC-SHA256(SERVER_SECRET, token))._token.<DDNS_ZONE>
```

Before an update or deletion, the service requires exactly one matching PTR,
checks that its target is a direct child of the configured zone, and verifies
the target's `TXT "ddns=1"` marker. The same PTR and TXT values are included as
RFC 2136 prerequisites, so the authoritative server checks them atomically with
the mutation.

Creating a hostname writes its marker and credential PTR in one update.
Updating replaces the A or AAAA RRset corresponding to the supplied address
while preserving the other address family. Deleting removes the hostname's
RRsets and credential PTR in one update. Records created by the service use a
60-second TTL.

## Requirements

The authoritative DNS server must:

- serve the configured DDNS zone on UDP port 53;
- support RFC 2136 Dynamic Update and RFC 8945 HMAC-SHA256 TSIG;
- accept the updates described above from the configured TSIG identity.

No particular authoritative DNS server implementation is required.

The TSIG key is read from a conventional key file:

```text
key "menhera-ddns-key." {
    algorithm hmac-sha256;
    secret "BASE64_ENCODED_SECRET";
};
```

## Configuration

Configuration is supplied through environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `SERVER_SECRET` | yes | Secret used to derive credential record names. Keep it stable and private. |
| `DDNS_ZONE` | yes | Managed DNS zone, for example `ddns.example.net.` |
| `UPDATE_KEY_PATH` | yes | Path to the HMAC-SHA256 TSIG key file. |
| `SERVER_ADDR` | no | Authoritative DNS server IP address. Defaults to `127.0.0.1`. |
| `LISTEN_ADDR` | no | HTTP listen socket. Defaults to `127.0.0.1:3001`. |

Example:

```sh
SERVER_SECRET='replace-with-a-long-random-secret' \
DDNS_ZONE='ddns.example.net.' \
UPDATE_KEY_PATH='/run/secrets/ddns-update.key' \
SERVER_ADDR='192.0.2.53' \
LISTEN_ADDR='127.0.0.1:3001' \
cargo run --release
```

## HTTP API

All endpoints use `POST` and return JSON. Successful responses contain
`"error": null`; failures contain a string in `"error"`.

### Create a hostname

```sh
curl -X POST 'http://127.0.0.1:3001/create?hostname=laptop'
```

The hostname must be one ASCII DNS label containing letters, digits, or
hyphens. The response contains the only copy of the bearer token:

```json
{"error":null,"token":"0123456789abcdef0123456789abcdef"}
```

### Update an address

```sh
curl -X POST \
  -H 'X-Real-IP: 192.0.2.10' \
  'http://127.0.0.1:3001/update?token=0123456789abcdef0123456789abcdef'
```

An IPv4 address replaces the hostname's A RRset; an IPv6 address replaces its
AAAA RRset. `X-Real-IP` is trusted as supplied, so the service should be exposed
only through a proxy that removes client-provided copies and sets the header
from the actual client address.

### Delete a hostname

```sh
curl -X POST \
  'http://127.0.0.1:3001/delete?token=0123456789abcdef0123456789abcdef'
```

The token becomes unusable after successful deletion.

## Build and check

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

Treat `SERVER_SECRET`, the TSIG key, and issued tokens as secrets. Changing
`SERVER_SECRET` invalidates all previously issued tokens because their DNS
credential names can no longer be derived.
