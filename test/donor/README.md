# A REALITY server and its donor, for testing the client against something breakable

`test/rig/server.json` is an Xray REALITY server; `test/donor/` is the site it fronts. Both are
built from `vendor/Xray-core`. Nothing in the Makefile builds or runs them — they are set up by
hand when a change needs a server that can be broken, restarted and instrumented, which the live
node cannot be.

## Why the keys are not here

They used to be. `test/donor/k.pem` was a 2048-bit RSA private key, `c.pem` a certificate issued to
`CN=www.avito.ru`, and both `server.json` files carried the same REALITY private key — committed,
pushed, and public. They were genuinely throwaway (no real server ever used that key), but a
private key in a repository is a private key in a repository, and the same value appearing in two
files is how a test key becomes a production one.

They are also two commands to regenerate, which is the whole argument for not storing them.

## Generating them

The REALITY keypair — put the private half in both `server.json` files and hand the public half to
the client as `PBK`:

```sh
docker run --rm ghcr.io/xtls/xray-core x25519
```

The donor's certificate, which only has to exist and be self-signed — `nginx.conf` expects these
two names in this directory:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj /CN=www.avito.ru -keyout k.pem -out c.pem
```

The subject matters only in that REALITY's `dest` and the client's SNI must agree with it; nothing
verifies the chain, because a client that fails REALITY authentication is supposed to receive the
donor's real content rather than an error. That is also how a wrong client is diagnosed: it gets
avito, not a failure.

The two client UUIDs in `server.json` are test identities and stay as they are — one plain, one
with `xtls-rprx-vision`, because the two paths through the client differ and both need proving.
