# The machine `make check` is meant to run on.
#
# It did not exist. The instructions said "the image lc-build:local is already in the system", which
# is true of one laptop and of nothing else — the environment every gate in this project is verified
# in could not be rebuilt from the repository at all, and the image that happened to be there was
# missing a Go toolchain, so five generated fixtures could only be produced OUTSIDE it. A green
# `make check` therefore depended on files the documented container cannot make.
#
#   docker build -t lc-build:local -f docker/Dockerfile .
#
# The cross-compiler is not here: it lives in dl/tc as a tarball in the repository, and the working
# tree is mounted at run time. Only what the host cannot carry belongs in the image.
FROM debian:trixie AS toolchains

# mbedTLS is the one dependency the device also has — 3.6.5 here against the 3.6.6 vendored for the
# cross build, which is deliberate: the tests are about formats and parsing, and running them against
# a slightly different patch level of the same library is a feature, not a slip.
#
# zlib is the second, and arrived with src/tls/certcomp.c: the hello offers certificate compression
# and something has to open what comes back. Headers and library both, because the source includes
# zlib.h like any other user of the library. The cross build gets the same header out of the tree —
# `ZLIB_INC=vendor/zlib`, beside `MBEDTLS_INC` and for the same reason: the OpenWrt toolchain tarball
# is a compiler and a libc and nothing else. That knob was documented at the top of the Makefile and
# missing from the mips target of the local build driver, so the cross build could
# not compile certcomp.o at all — and did not say so for a day, because an object left over from
# before that file existed satisfied make. A file that compiles differently in two of its three
# builds is a file whose second build nobody checks; this one now compiles the same way in all three.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libmbedtls-dev \
        zlib1g-dev \
        make \
        git \
        ca-certificates \
        curl \
        xz-utils \
        zstd \
        qemu-user \
        python3 \
        jq \
    && rm -rf /var/lib/apt/lists/*
# zstd is for `make tc-fetch`: OpenWrt ships its cross toolchains as .tar.zst, and GNU tar does not
# decompress zstd itself — it execs the zstd binary, so without it the unpack fails with "Cannot exec"
# and an error that reads like a corrupt archive. Until 2026-09-24 the toolchains were unpacked by
# hand and this image never had to.
# qemu-user is for check-arm64: the gate runs on x86-64, where src/tls/ghash.c takes the generic
# GHASH, and the PMULL path every arm64 router with the crypto extension takes would otherwise be
# compiled by the gate and never executed. qemu-aarch64 with `-cpu max` reports AES and PMULL in its
# hwcaps, so the same binary goes down the same path it goes down on an AX3000T.

# A REAL Go, not the gccgo that comes with GCC.
#
# `go version` in the old image answered "go1.18 gccgo", which is a Go 1.18 front end and refuses
# every tools/*/go.mod in this repository — they declare go 1.26. The fixtures they generate are the
# reference the C implementation is checked against: REALITY's key schedule transcribed from Xray,
# ML-KEM, the certificate shapes, BLAKE2b, the fingerprint capture. Without them `make check` is not
# a smaller suite, it is a suite that does not build.
ARG GO_VERSION=1.26.6
ARG GO_SHA256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
RUN curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    && echo "${GO_SHA256}  /tmp/go.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:/usr/local/bin:$PATH

# A SECOND GO, 1.27.3, FOR THE GENERATORS THAT STAND FOR THE XRAY REFERENCE. Xray v26.10.31 is built
# with Go 1.27.3, as the verified release binary reports. Its spider's HTTP/2 client, IDNA,
# net/url, which headers survive a redirect — is that Go's standard library. The hysteria reference is
# built with 1.26 and keeps the Go above. A tool whose go.mod says `go 1.27` is run with this one:
# the Makefile names it $(GO127), and the module seeding below picks it the same way.
ARG GO127_VERSION=1.27.3
ARG GO127_SHA256=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
RUN curl -fsSL -o /tmp/go127.tar.gz "https://go.dev/dl/go${GO127_VERSION}.linux-amd64.tar.gz" \
    && echo "${GO127_SHA256}  /tmp/go127.tar.gz" | sha256sum -c - \
    && mkdir -p /usr/local/go1.27 \
    && tar -C /usr/local/go1.27 --strip-components=1 -xzf /tmp/go127.tar.gz \
    && rm /tmp/go127.tar.gz

# Never fetch another toolchain. Left at its default, a go.mod asking for a version newer than the
# one installed sends Go to the network mid-build and the image stops being what it says it is.
ENV GOTOOLCHAIN=local

# The modules the reference tools import, resolved at build time so that generating a fixture does
# not need the network. go.sum is what makes this an assertion rather than a download: a module that
# does not match is a failed build here instead of a surprise later.
FROM toolchains AS module-inputs
RUN --mount=type=bind,source=tools,target=/inputs,ro \
    python3 -m unittest discover -s /inputs/imageinputs -p 'test_*.py' \
    && python3 /inputs/imageinputs/module_inputs.py /inputs /seed/tools

FROM toolchains
COPY --from=module-inputs /seed/tools/ /seed/tools/
# AND THE go.mod OF EVERY VENDORED MODULE A TOOL REPLACES ITSELF ONTO, at the same relative place.
# tools/salamander/go.mod says `replace github.com/apernet/hysteria/extras/v2 => ../../vendor/
# hysteria/extras`, so resolving it reads that directory's go.mod, and with only tools/ copied the
# image stopped building at all (2026-09-22: "open /seed/vendor/hysteria/extras/go.mod: no such file").
# The module file and its sums are what the resolution needs; the source stays in the mounted tree.
COPY vendor/hysteria/extras/go.mod vendor/hysteria/extras/go.sum /seed/vendor/hysteria/extras/
# tools/hpackdec and tools/hpackenc replace golang.org/x/net with vendor/x-net the same way.
COPY vendor/x-net/go.mod vendor/x-net/go.sum /seed/vendor/x-net/
# tools/qpackvec replaces github.com/quic-go/qpack with vendor/qpack the same way.
COPY vendor/qpack/go.mod vendor/qpack/go.sum /seed/vendor/qpack/
COPY vendor/Xray-core/go.mod vendor/Xray-core/go.sum /seed/vendor/Xray-core/
# The independent trust-anchor oracle compiles the actual QUIC handshake package,
# including its own uTLS v1.8.2 rather than the fingerprint tool's Xray uTLS.
COPY vendor/quic-go/go.mod vendor/quic-go/go.sum /seed/vendor/quic-go/
# tools/.goroot-x is made by the Makefile from GOROOT and may not be there yet; the tools that replace
# x/net and x/text onto it need only its two module files to resolve, and nothing from the network.
RUN mkdir -p /seed/tools/.goroot-x/net /seed/tools/.goroot-x/text \
    && echo 'module golang.org/x/net' > /seed/tools/.goroot-x/net/go.mod \
    && echo 'module golang.org/x/text' > /seed/tools/.goroot-x/text/go.mod
# Each with the Go its go.mod names: under GOTOOLCHAIN=local the 1.26 toolchain refuses a module
# that says `go 1.27`, and the second one resolves it.
RUN for d in /seed/tools/*/; do \
        [ -f "$d/go.mod" ] || continue; \
        g=go; grep -q '^go 1\.27' "$d/go.mod" && g=/usr/local/go1.27/bin/go; \
        (cd "$d" && $g mod download) || exit 1; \
    done \
    && cd /seed/tools/fp && go mod download -modfile=hysteria.mod \
    && cd /seed/tools/vendorcap/spiderredir/dest && /usr/local/go1.27/bin/go mod download \
    && cd /seed/vendor/Xray-core && /usr/local/go1.27/bin/go mod download \
    && cd /seed/vendor/quic-go && go mod download \
    && rm -rf /seed

# crypto/x509's TestX509Limbo downloads its pinned corpus outside any tools go.mod.
# Seed that exact toolchain dependency too, so the unmodified oracle runs offline.
RUN /usr/local/go1.27/bin/go mod download \
    github.com/C2SP/x509-limbo@v0.0.0-20260522003327-feb7caccc1af

# Whoever runs this owns the tree they mounted; git refuses to look at a repository owned by somebody
# else, and LC_VERSION comes from `git describe`. Without this the version stamp silently becomes
# "unknown" — which is exactly how a binary that had been deployed to a router was left unable to say
# which commit it was built from.
RUN git config --system --add safe.directory '*'

WORKDIR /w
