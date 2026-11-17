# Building lite-client

Everything here runs in Docker on an x86-64 host. Windows with Docker Desktop works too.

On Windows, run the commands below from WSL, or from Git Bash with `MSYS_NO_PATHCONV=1` set and
`$(pwd -W)` in place of `$(pwd)` and `$PWD`; otherwise Git Bash rewrites `/w` into a Windows path. A
working copy on NTFS is slow through a bind mount, and the OpenWrt SDK refuses to run on it at all,
which only matters for `make package` (see "The OpenWrt package").

On a fresh clone the order matters, and each step needs the one before it:

1. The upstream sources, into `vendor/`. The build image copies Go module files out of `vendor/`
   while it builds, so a `docker build` before them stops at
   `open /seed/vendor/hysteria/extras/go.mod: no such file`.
2. The build image, then the two cross toolchains.
3. The link stubs for both router targets.

Steps 1 and 2 need the network. Nothing after them does.

## 1. Upstream sources

```sh
sh tools/vendor/fetch.sh            # --force deletes and re-fetches every tree
```

This needs git 2.35 or later (`sparse-checkout set --cone`). Every tree is fetched at depth 1 by full
commit id, at the revision in the table under "Pinned revisions" below, and the large ones are
sparse: only the directories something compiles, cites or runs are checked out. The script also
initialises the two submodules the build needs (nghttp3's `lib/sfparse`, mbedTLS's `framework`),
sets zlib's `zconf.h` the way `./configure` leaves it on Linux, and turns off `core.autocrlf` and
turns on `core.longpaths` in each checkout. Citations are line numbers and several generators read
these files byte for byte, so a checkout converted to CRLF is wrong; mlkem-native's proof harnesses
have paths past Windows' 260-character limit. A tree already at its pin is left alone. A tree at
another revision is reported and the script exits non-zero.

`vendor/` is gitignored: nothing in it is committed here, and every tree keeps its own history and
licence (see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)). What each tree is for:

- **`Xray-core`**: the reference implementation. Everything this client does on the wire is defined
  by what Xray does: the client path is ~2300 lines (`proxy/vless`, `proxy/proxy.go` for Vision,
  `common/xudp`, `transport/internet/reality`), ported line by line and verified byte by byte
  against it.
- **`mlkem-native`**: ML-KEM-768. Required: without X25519MLKEM768 the REALITY handshake does not
  happen, and mbedTLS has no ML-KEM. Portable C90, memory safety proved with CBMC, no assembly
  backend needed.
- **`utls`**: the source of truth for fingerprint tables (`u_parrots.go`) and for the Fingerprinter,
  which turns a captured ClientHello back into a spec. The checkout matches the
  exact revision selected by the pinned Xray reference; see the table below.
- **`REALITY`**: the server half of REALITY, a fork of Go's crypto/tls. A read-only reference for
  what the client has to satisfy on the wire.
- **`mbedtls`**: AES, ChaCha20-Poly1305, SHA-2, HMAC, HKDF, X25519, and the bignum arithmetic the
  certificate checks run on. Already on the flash of every OpenWrt device (libmbedcrypto is 416 383
  bytes on a Mi Router 4A, from the libmbedtls package), so the checkout is only for headers. The
  X.509 parsing and path building a REALITY client needs when the server did not authenticate it
  are ported from Go 1.27.1 into `src/cert` (`goverify.h`) and checked against
  Go 1.27.3, rather than supplied by mbedTLS.
- **`zlib`**: headers for `src/tls/certcomp.c`. zlib itself is on every OpenWrt image (1.3.1), so this
  is the header half only, for the same reason as mbedTLS: the toolchain tarball is a compiler and a
  libc.
- **`brotli`** and **`zstd`**: the other two certificate-compression algorithms, decoders only,
  compiled into the binary. Neither is on an OpenWrt image. The Firefox fingerprint advertises
  zlib, brotli and zstd, and RFC 8879 section 4 lets the server pick any of them, so a client that
  cannot open all three fails on an ordinary reply. The encoders are used at build time only, by
  `tools/certcomp/gen.c`.
- **`brotli-go`**: the Go brotli reader uTLS opens a compressed certificate with. Not compiled, only
  read: `check-qgo-reasons` holds the client's error texts to it. v1.1.0 is what hysteria's `go.mod`
  selects.
- **`ngtcp2`** and **`nghttp3`**: QUIC and HTTP/3 for the Hysteria2 plane. Built from source and
  linked in; the OpenWrt feed packages are never installed ([DESIGN.md](DESIGN.md) says why).
- **`nghttp2`**: never linked into anything that ships, but `make check` does not build without it:
  the HPACK and HTTP/2 code is checked against it, and the HPACK static table is extracted from its
  source.
- **`hysteria`**, **`quic-go`** and **`utls-hy`**: the Hysteria2 reference, which nothing links or
  builds. `quic-go` is apernet's fork, the one hysteria pins, not quic-go/quic-go, and `utls-hy` is
  the uTLS v1.8.2 that fork builds with. `hysteria` needs `extras/` as well as `app` and `core`:
  Salamander and Gecko both live in `extras/obfs`.
- **`qpack`**: the QPACK encoder the quic-go fork writes the Hysteria2 authentication request with
  (v0.6.0, `vendor/quic-go/go.mod:7`).
- **`x-net`**: Go's x/net, sparse. Xray's XHTTP transport and the REALITY spider speak HTTP/2
  through it. Its `internal/httpcommon` is not optional, because that is where Go's client writes
  its request headers (`http2/write.go` is the server's encoder).

## 2. The build image and the toolchains

```sh
docker build -t lc-build:local -f docker/Dockerfile .
docker run --rm -i -v "$(pwd):/w" -w /w lc-build:local make tc-fetch
docker run --rm -i --network none -v "$(pwd):/w" -w /w lc-build:local sh .github/scripts/link-stubs.sh
```

The image is Debian with GCC, mbedTLS, Go 1.26.6 and Go 1.27.3. Go is there because many of the test
fixtures are generated by Go programs under `tools/`, and the image resolves their modules at build
time so that a check needs nothing but the tree. The tools that must match Xray v26.11.9 (built with
Go 1.27) run under 1.27; the rest under 1.26.

The cross compilers are deliberately not in the image. `make tc-fetch` downloads the OpenWrt 25.12.5
toolchains for `ramips/mt7621` (mipsel) and `mediatek/filogic` (aarch64) into `dl/tc` and
`dl/tc-a64`, and checks them against the release's own checksums. The last line makes the link
stubs both cross builds need, into `dl/mipslib` and `dl/a64lib`; "Cross-compiling for the router"
below says what they are.

`docker/Dockerfile.net` is a second image for exercising the transparent path (tproxy, marks, the
reply sockets) in a network namespace. It needs a kernel with `nft_tproxy`; the WSL2 kernel behind
Docker Desktop has none, so it does not work on Windows. `docker/Dockerfile.sdk` is for the package
build below.

## 3. Checking the tree

Production package releases use `package/release.mk` as their version source.
`LC_PACKAGE_BUILD=<positive pipeline number>` adds `_p<number>` to the base
version; `LC_GIT_VERSION=<commit>` stamps the actual executable. Both values
are passed to the SDK by the package qualification gate. APK/IPK qualification
receives `--package-build` and `--expected-version` and checks the installed or
extracted executable, not only the package filename. APK publication signs the
qualified bytes with the owner's RSA key; qualification never creates a release
trust root. Unsigned SDK inputs remain private build artifacts.

`make check` includes the Python 3 checkpoint/evidence analyzer tests. For the
full correctness gate plus the controlled reference spider-close oracle, use
`make check-spider-behavior`; see [SPIDER-ACCEPTANCE.md](SPIDER-ACCEPTANCE.md).
CANCEL/path frequencies remain diagnostics. Fresh build images include Python 3.

```sh
docker run --rm -i --network none -v "$(pwd):/w" -w /w lc-build:local make check
```

`--network none` is on purpose: it proves the check needs nothing outside the tree. Add
`rm -rf build &&` in front to prove it from nothing at all.

`make check` builds and runs every test suite on the host, builds every program for both router
targets (`check-device`), and runs the consistency gates: the pinned revisions below, the shipped
fingerprint table, citations into `vendor/`, the divergence register and others. It refuses to pass
when the cross toolchains or the link stubs are missing, instead of skipping the router build.

What `make check` does not cover is whether bytes actually arrive through a real server. For that
there are stands under `test/` that run the reference servers built from `vendor/`;
[TESTING.md](TESTING.md) describes them.

Plain `make` builds nothing. The first rule in the Makefile is `FORCE`, so the default goal has no
recipe and make answers "Nothing to be done for 'FORCE'". Ask for `all` by name.

## Cross-compiling for the router

The OpenWrt toolchain tarball is a compiler and a libc: no mbedTLS, and the copy on the device is
stripped of section headers, which `ld` will not link against. So the headers come from the vendored
mbedTLS (3.6.6, the version OpenWrt 25.12 ships) and the linker is given stub libraries that carry
nothing but the names this program asks for, under the right soname. At run time the real libraries
on the router resolve them.

There is a stub per soname: `libmbedcrypto` and `libz`, which the programs link, and `libmbedx509`
(everything named `mbedtls_x509_*`), which the script still makes and nothing has linked since
certificate verification became go1.27.1's own. Putting all names in one stub gives a binary whose NEEDED entry names a
library that does not define them. The file is what the linker opens (`-lmbedcrypto` finds
`libmbedcrypto.so`); the soname is what the binary records as its dependency and what the device
resolves.

`sh .github/scripts/link-stubs.sh`, run inside the build image from the root of the tree after
`make tc-fetch` (the last command of step 2), makes both sets, `dl/mipslib` and `dl/a64lib`. `dl/` is
gitignored, so on a fresh clone both have to be made before either target links. How it works, and
why it is done that way:

- The names come from the objects themselves. Both mipsel builds, the plain one and the
  `HYSTERIA=1` one, are compiled with `make -k`: there are no stubs yet, so the links fail, but every
  object gets built, and whatever the objects leave undefined under mbedTLS's and zlib's prefixes
  becomes a stub. Both builds are needed because the Hysteria2 build asks for names the plain build
  never mentions, and a stub made from one of them links that one and fails the other.
- The aarch64 set is the mipsel set built with the other compiler. The names do not depend on the
  architecture (same sources, same calls), and the set made from both mipsel builds is the widest
  one. Generating the aarch64 set from one binary alone is how a stub ends up short:
  `build-a64/bench-aead` once failed to link on three `mbedtls_cipher_*` names that `lc-tunnel` never
  uses.
- A source file that does not compile leaves its names out of the stubs. That is not hidden: the
  gate then fails in `check-device` on the compile error itself.

Run it again whenever the set of mbedTLS or zlib calls changes. A stub that is short by a name shows
up as a link failure that looks like a broken cross build.

With the stubs in place, a binary to copy onto a device:

```sh
# The toolchain is picked by what is IN it, not by a glob: dl/tc can hold more than one.
TC=$(ls -d dl/tc/*/toolchain-*/ | while read d; do
        [ -x "$d/bin/mipsel-openwrt-linux-gcc" ] && echo "${d%/}"; done | head -1)
export PATH=$PWD/$TC/bin:$PATH STAGING_DIR=$PWD/$TC

make BUILD=build-mips HYSTERIA=0 CC=mipsel-openwrt-linux-gcc \
     MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB=dl/mipslib all
```

`HYSTERIA=1` adds the Hysteria2 plane. For aarch64 (the AX3000T and other `mediatek/filogic` boards)
use the toolchain under `dl/tc-a64`, `CC=aarch64-openwrt-linux-gcc` and `MBEDTLS_LIB=dl/a64lib`.

`make check` builds both targets with both plane settings once the stubs exist (`check-device`).

The standalone cross build is not hardened the way the package is. `-D_FORTIFY_SOURCE=2` only has an
effect on musl when OpenWrt's `fortify-headers` are on the include path, and they are only there in
the SDK build. Counted as MIPS `break` instructions (the headers inline `__builtin_trap()`), the
package build has 99 fortify checks and the standalone build 25. The Makefile explains this next to
the flag. For anything you install on a router, use the package.

## The OpenWrt package

`package/Makefile` produces two packages from one source, `lite-client` (REALITY only) and
`lite-client-hysteria` (both planes). Both install `/usr/sbin/lc-tunnel`,
`/etc/init.d/lite-client`, `/etc/config/lite-client` and `/etc/lite-client/fingerprint.fpt`, plus
the conffiles entries that carry credentials across a sysupgrade. The SDK adds
missing conffiles (owner-created credentials) to `/lib/upgrade/keep.d/<package>`;
the install function alone is not the complete package payload.

```sh
make sdk-fetch          # 219 MB into dl/, checksum pinned in the Makefile
docker build -t lc-sdk:local -f docker/Dockerfile.sdk .
```

Then, from the root of a git clone of this repository (the recipe runs `git describe` there, and a
tree without `.git`, such as an unpacked archive, stamps every binary `unknown`):

```sh
docker run --rm -it -v "$PWD:/repo" -v lc-sdk-2512:/sdk lc-sdk:local sh
  # once per volume:
  tar --zstd -xf /repo/dl/openwrt-sdk-*.tar.zst -C /sdk
  chown -R build:build /sdk
  su build -c 'cd /sdk/openwrt-sdk-*/ && ./scripts/feeds update base &&
               ./scripts/feeds install libmbedtls zlib ca-bundle ip-full && make defconfig'
  # every build:
  su build -c 'cd /repo && make package'
```

The packages land under the SDK's `bin/packages/`. With the 25.12 SDK they are `.apk` files; an SDK
of a release that still uses opkg (24.10) produces `.ipk`.

For local APK qualification in the same SDK environment, use a fresh output path:

```sh
make check-package BUILD=/tmp/lc-package-review \
  CONFIG_SIGNED_PACKAGES= CONFIG_SIGNED_IMAGES=
```

This builds unsigned local test artifacts without creating signing keys, then
uses the SDK's APK tool and real local dependency packages to install and upgrade
both variants in disposable roots (usermode when unprivileged). Package scripts and network access
are disabled. A synthetic older package tests preservation of owner-modified
config and late-created credentials, and replacement of managed files; it is
not a historical-client migration test. The actual packaged MIPS or AArch64 executable runs
under qemu to check plane support. Receipts remain in `BUILD/package-check`;
an existing receipt directory is refused. This does not test procd, firewall,
firmware sysupgrade or execution on hardware. No package is installed on a router.
For an archive build without Git metadata, stamp the package explicitly with
`LC_GIT_VERSION=<revision>` and pass the same revision to the qualification
script's `--expected-version` option; unidentified binaries are rejected.
For 24.10 IPKs, use:

```sh
python3 test/config/check_ipk.py --sdk <sdk> --output <fresh-directory> \
  --expected-version <revision>
```

This checks both package payloads and executes the packaged binaries under
QEMU. It does not exercise opkg installation or hooks.
The same target also executes the SDK's real `rc.common` with simulated
UCI/procd/kernel commands; lifecycle receipts go to `BUILD/service-check`.
This checks shell ordering and cleanup, without running a procd daemon or
modifying a kernel ruleset.
Both commands use the Makefile's exact default path to the pinned MT7621 SDK.
If overriding `SDK_DIR`, pass an exact directory: a `*` inside a Make variable
assignment is not expanded into the SDK directory by these recipes.

`make sdk-fetch` fetches the `ramips/mt7621` SDK. `make sdk-fetch-aarch64` fetches
the separately SHA256-pinned `mediatek/filogic` SDK (25.12.5, GCC 14.3.0).
Unpack it into its own Linux volume, prepare the same feeds and pass its exact
directory as `SDK_DIR`. APK qualification reads the SDK's configured package
architecture and selects qemu-mipsel or qemu-aarch64; unsupported or ambiguous
architectures fail before installation. Other SDK targets need separate qualification.

Four things here are not preferences. Each one cost a failed run.

**The SDK goes in a container volume, not in the working tree.** OpenWrt refuses to build on a
case-insensitive filesystem, a Docker bind mount from Windows (or from macOS with a default APFS
volume) is one, and `FORCE=1` only postpones the damage. It is also far slower: 3 min 56 s to unpack
into the bind mount against 5.4 s into a container volume.

**A bare SDK has no mbedTLS.** Its `package/` holds only `kernel` and `toolchain` until the base feed
is installed. Skip the feed step and the build dies on `mbedtls/platform_util.h: No such file or
directory`. The feed step needs the network once.

When reusing a verified feed checkout, check that `feeds/base` resolves to
`base_root/package` before rebuilding its index. The pinned SDK initially links
it to `../package`; copying `base_root` and running only `feeds update -i` can
leave that link unchanged and index just the SDK's kernel/toolchain packages.
The documented fresh `feeds update base` creates the correct link during clone.
Verify the installed `package/feeds/base/mbedtls/Makefile`, not just index success.

**`clean` is not optional.** `Build/Prepare` copies the sources into `PKG_BUILD_DIR` once, behind a
`.prepared` stamp, so editing a file and rebuilding compiles the old copy and reports success.
`make package` runs the clean for you; a bare `package/lite-client/compile` does not.

**Do not build as root.** OpenWrt declines, which is why the image has a `build` user.

## Local kernel-rule qualification

These optional gates need a private Docker network namespace, NET_ADMIN and real
`ip`/`nft` tools. They are not part of the standard host/cross or SDK gates.
From the lite-client repository root, after building `lc-build:local`:

```sh
docker build -t lc-nettest:local -f docker/Dockerfile.nettest .
mkdir -p build/kernel-artifacts
docker run --rm --init --network none --cap-add NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  -e LC_KERNEL_TEST_ISOLATED=1 \
  -v "$PWD:/repo:ro" -v "$PWD/build/kernel-artifacts:/out" -w /repo \
  lc-nettest:local make BUILD=/out check-kernel-rollback
```

The guard requires Docker, explicit isolation acknowledgement and only a loopback
interface. Never use host networking. A fresh output directory is required.
The rollback gate checks real policy rules, local routes, nft transactions and
preservation of unrelated state. Route and nft errors are injected at the command
boundary; cleanup is performed by the real kernel tools.

For successful TPROXY installation as well, use `check-kernel-tproxy` with a fresh
output path. The Python probe exits 77 if the kernel lacks the socket expression
needed by the ruleset; Make reports a failed target. Other installation errors
also fail the gate. Rollback success alone does not
qualify successful interception. JSON receipts explicitly separate these results.
Neither gate forwards traffic, starts procd, installs a package or modifies a router.

## Guest-kernel TPROXY qualification

When the host kernel lacks nft socket/TPROXY expressions, `check-vm-tproxy`
boots a pinned x86 OpenWrt guest under QEMU TCG. Host kernel modules and KVM
are not needed. The guest has no disks or network adapters and runs a dedicated
test init instead of procd. No SSH daemon, key generation or package installation
scripts run. This qualifies kernel rule installation and cleanup, not traffic
forwarding, a client binary, hardware compatibility or throughput.

The image/rootfs, four matching kernel-module APKs, ip-full and two additional
libraries have SHA-256 pins in `test/rules/vm-inputs.json`. The remaining ip-full
dependencies are present in the pinned factory rootfs. Inputs come from the
[official OpenWrt 25.12.5 download directories](https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/).
Download is explicit and the boot gate accepts only matching cached bytes.
Use the SDK prepared for package checks above as the host APK decoder:

```sh
docker build -t lc-vmtest:local -f docker/Dockerfile.vmtest .
docker run --rm -v "$PWD:/repo" -w /repo lc-vmtest:local make vm-nettest-fetch
mkdir -p build/vm-artifacts
docker run --rm --init --network none \
  -v "$PWD:/repo:ro" -v lc-sdk-2512:/sdk:ro \
  -v "$PWD/build/vm-artifacts:/out" -w /repo \
  lc-vmtest:local make BUILD=/out check-vm-tproxy
```

The container uses its default user to create the guest's console device in a
temporary initramfs tree. No host NET_ADMIN, privileged container, kernel-module
mount or device passthrough is required. The case-sensitive temporary root is
inside the container; console, initramfs, kernel snapshots, hashes and JSON
receipts remain in `BUILD/vm-tproxy`. The guest must shut down and report success
within 120 seconds, its snapshots must pass semantic checks, and inputs/source
must remain unchanged. Existing receipt directories are refused.

## Actual service and upgrade qualification

`check-vm-service` uses the same diskless OpenWrt VM plus the pinned veth module
in `test/rules/vm-service-inputs.json`. It runs real procd/ubus, rc.common and APK
hooks, with an internal LAN/backend namespace pair. There are no external NICs,
host network capabilities or production endpoints. The SDK must be the matching
**x86-64** SDK named and hashed in that manifest; MIPS packages cannot run in
this guest. Build both package variants with that SDK first.

Inside the documented build environment, with a populated offline Go module
cache and a writable private output mount:

```sh
make vm-service-fetch VM_CACHE=/cache/vm-inputs
make vm-service-bundle SDK_DIR=/sdk/openwrt-sdk-25.12.5-x86-64_gcc-14.3.0_musl.Linux-x86_64 BUILD=/out
# Run this step in docker/Dockerfile.vmtest, with --network none:
make check-vm-service VM_CACHE=/cache/vm-inputs BUILD=/out
```

Bundle preparation builds the pinned full Xray and a standalone Go test peer,
checks package payloads against the current init/fingerprint sources, and creates
disposable test identities. The controlled predecessor contains the real
REALITY-only executable under the full package's name at version 0.0.9; it is not
a historical release. The actual full APK must replace its running image and
every worker. Retain the private bundle, initramfs and serial logs together;
they contain fixture credentials and the configuration backup.

The gate checks independent backend receipts for TCP, TLS and UDP, one/four-worker
respawn, reload, real upgrade hooks, disabled/invalid starts, occupied ports and
automatic recovery without removing interception. It then runs `sysupgrade -b`,
checks default secret/config contents and mode 0600, boots a fresh root, runs
`sysupgrade -r`, and verifies identical restored files and fresh traffic.
Each boot has a 300-second timeout; a 512 MiB VM allocation is a test setting,
not a device minimum. Source/input changes and existing output paths are refused.
This qualifies configuration backup/restore across boots, not firmware flashing,
physical reboot behavior, performance or router installation.

## The fingerprint table

`package/files/fingerprint.fpt` is the Firefox ClientHello the REALITY plane sends, packed into a
table. It is committed because producing it needs Go and uTLS, and the SDK has neither.

```sh
make fingerprint      # capture firefox from uTLS and derive the packed table
```

`make check` regenerates it and compares byte for byte (`check-fingerprint`), and also checks that
`tools/fp/go.mod` and `vendor/Xray-core/go.mod` pin the same uTLS. Raising either pin means
regenerating the table and `test/fphello/reference_firefox.h` in the same commit.
[DESIGN.md](DESIGN.md) explains why the Firefox table is reproducible and a Chrome one is not.

## Sizes

Stripped `lc-tunnel` from the recorded standalone cross build of 2026-11-05, and the same
binary through `gzip -9 -n` as a rough idea of the download:

| target | variant | stripped | gzip -9 -n |
|---|---|---|---|
| mipsel_24kc (ramips/mt7621) | REALITY only | 921 732 B | 412 979 B |
| mipsel_24kc (ramips/mt7621) | with Hysteria2 | 1 449 108 B | 665 117 B |
| aarch64_cortex-a53 (mediatek/filogic) | REALITY only | 788 440 B | 375 016 B |
| aarch64_cortex-a53 (mediatek/filogic) | with Hysteria2 | 1 116 240 B | 562 662 B |

The package build differs slightly (different flags, the fortify headers). The size target the
project set itself is 1.5 MB on flash for the binary. mbedTLS, zlib and the CA bundle are already on
a stock image, so they cost nothing extra. All four standalone binaries remain
below 1,500,000 bytes. These are binary sizes, not installed SDK package sizes;
account separately for package files and dependencies missing on the target.
Per the owner's 5 November clarification, RAM counters are diagnostic without
a MemAvailable floor or RSS cap in current native checkpoint plans.

Where the Hysteria2 half goes, measured for mipsel at `-Os` with dead code removed against the entry
points a client calls:

    ngtcp2 core          262 816   295 008 for the whole archive
    nghttp3              102 192   of which 52 300 is QPACK
    shared.c              11 816   ngtcp2's backend-independent half, unmodified
    our crypto backend     5 772   qcrypto, qtls, shim

Of the REALITY build, about 243 KB on mipsel is the brotli and zstd decoders (166 KB of it brotli,
122 KB of that its static dictionary).

## Pinned revisions

These are the revisions this tree is audited and built against. `check-vendor` (part of
`make check`) reads this table and fails when a checkout under `vendor/` is somewhere else, so
change a row only together with the checkout, and keep `tools/vendor/fetch.sh` in step. Every
`vendor/<tree>/file:line` citation in the code means the text at these revisions.

| tree | revision | describe |
|---|---|---|
| `Xray-core` | `676eaf66` | `v26.11.9` |
| `REALITY` | `4bb46b2` | — |
| `utls` | `a13c59f` | `v1.8.3-0.20261108164504-a13c59ffe98b` |
| `utls-hy` | `8fe0b08` | `v1.8.2` |
| `mlkem-native` | `c4f993c3` | `v2.0.0-1-gc4f993c3` |
| `mbedtls` | `0bebf8b8c7` | `v3.6.6` |
| `zlib` | `51b7f2ab` | `v1.3.1`, the version OpenWrt ships |
| `brotli` | `ed738e8` | `v1.1.0` |
| `zstd` | `f8745da` | `v1.5.7` |
| `brotli-go` | `17e5901d` | `v1.1.0` (andybalholm/brotli) |
| `ngtcp2` | `d7fb3ed0` | `v1.25.0-8-gd7fb3ed0` |
| `nghttp3` | `e4988cd` | `v1.18.0-5-ge4988cd` |
| `nghttp2` | `fe17ea5` | — |
| `hysteria` | `ca8fbd8` | `app/v2.13.0` |
| `quic-go` | `a10df75c` | `v0.63.1-0.20261004180939-a10df75c260c` |
| `qpack` | `1661efa7` | `v0.6.0` |
| `x-net` | `3de643db` | `v0.62.0`, sparse: `http2`, `internal/httpcommon`, `internal/httpsfv`, `internal/gate`, `internal/testcert`, `idna`, `http/httpguts` |
| `bearssl` | — | not recorded; no longer compiled since 2026-09-21 |

`zlib` and `bearssl` are skipped by the check: zlib names a release, which is enough to re-fetch it,
and `vendor/bearssl` is a source drop of three GHASH files kept from before `src/tls/ghash.c`
replaced them. Its revision was never written down and cannot be read back off the files, and
nothing reads it any more, so `tools/vendor/fetch.sh` does not fetch it.

Three notes on specific rows:

- **`utls` matches Xray's module revision exactly.** The citation tree and
  `tools/fp/go.mod` both pin `a13c59ffe98b`, the revision in Xray v26.11.9.
  The capture tool runs on Go 1.27.3, including its tests and module lookup.
- **`utls-hy` is a second uTLS**, the one the quic-go fork builds with (`vendor/quic-go/go.mod:8`).
  Since hysteria 2.11 the QUIC handshake runs through it while the client parrots Chrome, so
  citations about that handshake point here. The `fp-hysteria` generator uses
  `tools/fp/hysteria.mod` and Go 1.26, independently of Xray's `fp` executable.
- **`x-net` now matches Xray's v0.62.0 dependency exactly.** Its independent
  header/trailer budgets and Go 1.27.3's lazy outbound-window overflow checks
  have dedicated executable oracles. Hysteria's QPACK generator keeps its own
  v0.58.0 module dependency instead of inheriting the REALITY plane's new pin.
