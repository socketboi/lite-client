# Contributing to lite-client

lite-client is a small C client for OpenWrt routers that reproduces two reference implementations
on the wire: Xray-core v26.11.9 with XTLS REALITY and uTLS for the VLESS + XTLS-Vision plane, and
hysteria app/v2.13.0 on its quic-go fork for the Hysteria2 plane. Where the references run on Go's
standard library (Go 1.27 for Xray-core, Go 1.26 for hysteria), that library is part of the
reference too.

Most of what follows comes from one rule, so it goes first.

## The rule: behave like the reference

The client is useful only as long as nobody can tell it from the reference client. A change that
makes it "better" than the reference makes it different, and different is detectable. So:

1. Behaviour matches the reference, byte for byte and decision for decision. That covers what goes
   on the wire, and also when things happen, how errors close a connection, what is retried and
   what is given up.
2. Every behavioural claim in the code cites the reference file and line.
3. Any deviation is a defect. Known ones are recorded in [DIVERGENCES.md](DIVERGENCES.md) with
   their reason (see "Differences from the reference" below). You can add or close a "not yet
   ported" row yourself; a new deliberate difference, a "maintainer's decision" row, needs the
   maintainer's agreement in an issue first.
4. Tests take their expected answers from the reference code itself wherever that is possible.
5. A new test must fail when the fix it covers is reverted.

If you think the reference is wrong, fix it upstream first. We follow when the reference changes.

### Citing the reference

Reference trees live in `vendor/`, one directory per project, at the revisions pinned in the
repository. A citation is the path inside the tree and a line or a range:

```
vendor/<tree>/<path>:<line>
vendor/<tree>/<path>:<first>-<last>
```

Put it in the comment next to the code that follows it, and say what the reference does, not only
where. When the code is subtle, quote the lines. Two examples from the tree:

```c
/* One flow and the absence of one is the whole set (vendor/Xray-core/proxy/vless/vless.go:9-10).
 * Refused here rather than sent, because a third string used to travel in the addons block while
 * the framing beside it stayed plain, which the node answers with silence. */
if (lc_vless_flow(flow) < 0) {
```

```c
/* The reference verifies the chain against the system roots when REALITY did not authenticate
 * the node:
 *
 *     opts := x509.VerifyOptions{ DNSName: c.ServerName, Intermediates: x509.NewCertPool() }
 *     for _, cert := range certs[1:] { opts.Intermediates.AddCert(cert) }
 *     if _, err := certs[0].Verify(opts); err != nil { return err }
 *                    (vendor/Xray-core/transport/internet/reality/reality.go:104-114)
 */
```

A bare `:N` later in the same comment refers to the last file named. For Go's standard library
write `GOROOT/src/<path>:<line>` and name the Go version, since the line numbers move between
releases.

`make check-cites` fails when a citation names a file that does not exist or a line past its end.
It also runs `tools/cites/claims`, which checks that code quoted in a comment and the functions it
names are where the citation says. It cannot check that your sentence is true; the reviewer will
open the file and read it.

Moving a pin (a new Xray-core or hysteria release) is maintainer work. Every citation is carried to
the new revision with `tools/cites/claims -remap`, and the ones whose lines changed are reread.

### Differences from the reference

[DIVERGENCES.md](DIVERGENCES.md) is the only list of places where this client knowingly behaves
differently. Each row has an ID (a letter and a number, for example `Q7` or `O2`), and the code
carries a `DIVERGES: <id>` comment at every place the difference lives. `make check-divergences`
fails on a mark without a row or a row without a mark, and prints the count on every run.

A row sits in one of three sections:

- **not yet ported**: the reference does something we do not do yet. This is a known defect, and
  a fix removes the row and the marks in the same commit.
- **Go's runtime**: the reference's behaviour comes from the Go scheduler, garbage collector or
  resolver rather than from its code, and cannot be reproduced exactly (the order two goroutines
  happen to run in, for example).
- **the maintainer's decision**: a deliberate difference. So far these only change how work is
  spread over CPU cores, with the bytes on the wire unchanged. A new one needs the maintainer's
  agreement in an issue before the pull request.

If you find a difference that is not listed, that is a bug report (see "Reporting a wire
difference" below) or a row plus marks in your pull request. If you fix one, strike the row off.

### Tests

Where the reference can be run, the expected answers come from running it. Programs under
`tools/` do this: they build against the vendored reference (through a `replace` in their
`go.mod`) or against the Go toolchain the reference is released with, and write a C header of
vectors that a suite under `test/` holds our code to. Some headers are generated into
`build/gen/` on every build. Others are committed as `test/<suite>/reference*.h`, and the tool
that writes one says in its header how to regenerate it (`tools/x509read/main.go` for
`test/x509go/reference.h`, for example). Hand-written expected values are fine only where the
reference cannot be run, and then they carry a citation like any other claim.

Every suite prints an `ok` line per passing check and must print at least one; a suite that
asserts nothing fails the gate.

**Mutation check.** Before opening a pull request, revert your fix while keeping the test, rebuild
and run the suite. It must fail, on a line that names the case. Then break the code in the other
ways the test claims to catch. Say in the pull request what you broke and what failed. Work on a
copy of the file (`cp src/quic/foo.c /tmp/foo.c.orig`, then copy it back), not with
`git checkout`, which also throws away the uncommitted fix.

## Setting up

You need git and Docker on an x86-64 machine. Everything else runs inside the build image, which
installs the amd64 Go toolchains, and the OpenWrt toolchains are x86-64 binaries as well; on Apple
silicon, build and run the image with `--platform linux/amd64` and expect it to be slow. Plan for
several GB of disk: the reference trees, the image, and two OpenWrt toolchains.

The order matters, because each step needs the one before it:

```sh
git clone https://github.com/socketboi/lite-client
cd lite-client

# 1. The reference trees. Every one is cloned into vendor/ at its pinned revision.
#    vendor/ is never committed.
sh tools/vendor/fetch.sh

# 2. The build image. It copies go.mod files out of vendor/, so it needs step 1.
docker build -t lc-build:local -f docker/Dockerfile .

# 3. The OpenWrt 25.12.5 toolchains for mipsel and aarch64, into dl/, checked against the
#    sha256 pinned in the Makefile.
docker run --rm -v "$PWD:/w" -w /w lc-build:local make tc-fetch

# 4. Link stubs for the cross builds (see "Cross-compiling" below).
docker run --rm --network none -v "$PWD:/w" -w /w lc-build:local sh .github/scripts/link-stubs.sh
```

Steps 1 to 3 need the network. Nothing after them does.

On Windows, see the note at the top of [docs/BUILD.md](docs/BUILD.md): run these from WSL, or from
Git Bash with `MSYS_NO_PATHCONV=1` and `$(pwd -W)`.

## The gate

```sh
docker run --rm --network none -v "$PWD:/w" -w /w lc-build:local make check-spider-behavior
echo $?
```

`make check` builds every program, runs every suite under `test/` (each with a 120 second limit),
then runs `check-builds`: the static checks (citations, names and file pointers in comments, the
divergence registry, the fingerprint tables against uTLS, every vendored tree at its pinned
revision), both build configurations, the version stamp, and a live certificate compression check
against OpenSSL. It ends with `check-device`, every program built for mipsel and aarch64 with and
without the Hysteria2 plane, and `check-arm64`, which runs the AES-GCM and ChaCha20 code on its
arm64 paths under qemu.

`make check-spider-behavior` runs that complete gate and then the controlled
Go/C spider-close oracle. CI and the pull request checklist require this target;
see [spider acceptance](docs/SPIDER-ACCEPTANCE.md) for its scope and criteria.

**Green means the exit status is 0.** Do not read the output for `FAIL` lines: a build that breaks
before the suites run prints no `FAIL` at all, and a pipe into `tail` or `tee` hides the status
unless you set `pipefail`. The gates fail rather than skip when something they need is missing
(a toolchain, the stubs, qemu, OpenSSL), so a missing tool shows up as red, not as a shorter green
run.

`--network none` is deliberate: the image resolves every Go module at build time, and a test
that needs the network is a bug.

The first run compiles mbedTLS, mlkem-native, brotli, zstd and the QUIC stack for three targets and
takes a while; later runs reuse `build/`. Add `rm -rf build &&` in front to prove a change from
nothing. To run one suite or one gate:

```sh
docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c 'make build/test-hkdf && build/test-hkdf'
docker run --rm -v "$PWD:/w" -w /w lc-build:local make check-cites
```

Not in the gate, but expected when you touch the code they cover:

- `sh test/hystand/run.sh` runs the reference Hysteria2 server built from `vendor/` and pushes
  traffic through our client. Use it for anything on the Hysteria2 data path.
  `test/hystand/README` explains how to break the client on purpose and watch the stand catch it.
- `docker/Dockerfile.net` is an image for the tproxy path. It needs a privileged container on a
  Linux kernel with `nft_tproxy`; Docker Desktop's WSL2 kernel does not have it.

[docs/TESTING.md](docs/TESTING.md) describes the suites and gates in more detail.

## Cross-compiling

`make check` already builds everything for both routers. To get a binary to copy onto a device:

```sh
docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c '
  TC=$(ls -d dl/tc/*/toolchain-*/ | while read d; do
         [ -x "$d/bin/mipsel-openwrt-linux-gcc" ] && echo "${d%/}"; done | head -1)
  export PATH=$PWD/$TC/bin:$PATH STAGING_DIR=$PWD/$TC
  make BUILD=build-mips HYSTERIA=0 CC=mipsel-openwrt-linux-gcc \
       MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB=dl/mipslib all'
```

`HYSTERIA=1` adds the Hysteria2 plane. For aarch64 use `dl/tc-a64`, `aarch64-openwrt-linux-gcc`
and `dl/a64lib`. Name the `all` target: plain `make` builds nothing.

The OpenWrt toolchain has no mbedTLS or zlib, and the libraries on a router are stripped so that
`ld` cannot link against them. The binaries are therefore linked against stub libraries that carry
the right names and sonames, and the router's real `libmbedcrypto` and `libz` resolve them at run
time. `sh .github/scripts/link-stubs.sh` makes the stubs from the objects; run
it again when the code starts calling a new mbedTLS or zlib function. "Cross-compiling for the
router" in [docs/BUILD.md](docs/BUILD.md) explains how.

The OpenWrt package is built with the SDK (`make sdk-fetch`, the image in `docker/Dockerfile.sdk`,
then `make package`); docs/BUILD.md has the details.

## Reporting a wire difference

A wire difference is a report that our client does something the reference client does not: a
different byte in a ClientHello, a different record or datagram size, a different reaction to a
server's message, a different way of closing. File it with the "Wire difference" issue form.

If the difference would let an observer or a prober pick out users of this client, report it
privately through the Security tab instead (see [SECURITY.md](SECURITY.md)).

The report needs captures from both clients. Run the reference client and ours against the same
server with the same settings (fingerprint, flow, SNI, Chrome parrot, obfuscation, receive rate),
from the same machine, one after the other. A capture of our client alone shows nothing. Give the
exact versions of both clients and of the server.

Capture one connection each if you can. The single-purpose tools make exactly one connection on a
host build (`build/lc-fetch` for REALITY, `build/lc-hyfetch` for Hysteria2), which keeps router
noise out of the capture. On the reference side that is `xray run -c config.json` with a SOCKS
inbound and `curl --socks5-hostname`, or `hysteria client -c config.yaml`. Include the capture
commands, for example:

```sh
tcpdump -i any -s 0 -w ours.pcap 'host NODE and tcp port 443'
tcpdump -i any -s 0 -w reference.pcap 'host NODE and tcp port 443'
```

For Hysteria2 capture the UDP port instead, or the whole range if the node uses port hopping.

For the REALITY ClientHello there is a direct comparison that needs no server. `fp` renders the
reference's hello from uTLS, `lc-hello` renders ours from the shipped table, and `fp diff` ignores
exactly the fields that are random per connection:

```sh
docker run --rm -v "$PWD:/w" -w /w lc-build:local sh -c '
  make build/fp build/lc-hello &&
  build/fp dump -fp firefox -sni www.example.com -o /tmp/ref.bin &&
  build/lc-hello package/files/fingerprint.fpt www.example.com /tmp/ours.bin &&
  build/fp diff /tmp/ref.bin /tmp/ours.bin'
```

Use throwaway credentials for anything you attach. A capture holds the node address and the SNI,
and a TLS key log or a qlog decrypts the session.

## Commit messages

One line, in English:

```
type(scope): what changed, in the reference's terms
```

`type` is one of `fix`, `feat`, `perf`, `test`, `docs`, `build`, `ci`, `refactor` or `chore`.
`scope` is the module or tool the change is about (`reality`, `vless`, `tls`, `cert`, `fp`,
`quic`, `h2`, `net`, `core`, `tunnel`, `package`, `tools`), or `lite-client` for a change across
the tree. When a change closes or adds a row of the divergence registry, end with its ID:

```
fix(quic): close with quic-go's reason when the server certificate does not parse (Q7)
perf(reality): open REALITY records on all cores, wire unchanged (O3)
test(hpack): take the HPACK vectors from x/net at the revision Xray-core pins
```

The reasoning goes into comments next to the code, where the next reader will find it, and not
into the commit body. The body holds only trailers: `Signed-off-by:` (required, see below) and
`Co-authored-by:` if someone else worked on the change.

## Developer Certificate of Origin

Contributions are accepted under the project's license, MPL-2.0, and every commit must be signed
off. By adding the line

```
Signed-off-by: Your Name <you@example.com>
```

you certify the Developer Certificate of Origin below: that you wrote the change or otherwise have
the right to submit it under the project's license. It is not a copyright assignment; you keep
your copyright. Use the name and email you commit with. A pseudonym you use consistently is fine,
an anonymous or throwaway identity is not.

`git commit -s` adds the line for you. To sign off commits you already made:

```sh
git commit --amend -s --no-edit        # the last commit
git rebase --signoff main              # every commit on your branch
```

CI checks that every commit in a pull request carries a sign-off matching its author's email.

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Pull requests

1. For anything larger than a cited fix, open an issue first. A new row in the "maintainer's
   decision" section always needs an issue and the maintainer's agreement before any code.
2. Fork the repository and branch from `main`:

   ```sh
   git switch -c fix/hy-close-reason main
   ```

3. Keep to one logical change. A behaviour change, its test, its citations and its registry row
   belong together in one pull request; an unrelated cleanup you noticed on the way does not.
4. Write the test first and watch it fail on `main`. Then fix, then do the mutation check.
5. Update what the change touches: [DIVERGENCES.md](DIVERGENCES.md) and the `DIVERGES:` marks when
   a difference is added or closed, [docs/TESTING.md](docs/TESTING.md) when you add a suite or a
   gate, README.md when a user sees the change, and the unreleased section of
   [CHANGELOG.md](CHANGELOG.md). A change to ngtcp2 is a new numbered patch in `patches/ngtcp2/`
   (see its README), never an edit inside `vendor/`.
6. Run `make check-spider-behavior` and check the exit status.
7. Push and open the pull request against `main`. Fill in the template, including the citations
   and what the mutation check broke.
8. CI must pass: the full gate, the router builds, and the sign-off check. The router build job
   also uploads stripped binaries, which is a quick way to try a change on a device.

Usually a pull request is one commit. If it needs more, each commit must build and pass the gate on
its own. Expect review questions of the form "where does the reference do this?"; the answer is a
file and a line.

## What will not be accepted

- Behaviour "improvements" over the reference without a registry row the maintainer approved.
  That includes extra retries, different timeouts, stricter or looser parsing, and different error
  handling, even where ours would arguably be better.
- Upstream code committed into the repository. `vendor/` is fetched, never committed; changes to
  upstream code are patches under `patches/`.
- Reformatting, whitespace or renaming changes on their own.
- Features the reference client does not have, and growth outside the project's scope: a server
  side, a routing engine, a JSON configuration, another protocol.
- Tests changed to pass instead of code changed to be right, and gates turned from failing into
  skipping.

## Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Security issues go through
[SECURITY.md](SECURITY.md), not the issue tracker.
