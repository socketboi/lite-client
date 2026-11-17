# lite-client
#
# Everything generated lands in build/ and nothing else: no object files next to sources, no
# generated headers in the source tree. That is not tidiness for its own sake — a generated file
# sitting among hand-written ones eventually gets edited by hand, and the edit is lost on the next
# build without anyone noticing.
#
# CC is overridden by the OpenWrt SDK when cross-compiling; the default builds for the host.

CC      ?= cc
BUILD   ?= build
PYTHON  ?= python3

# What of a rule’s prerequisites is actually a source file. Everything else on the line is there to
# make the rule fire — headers, generated fixtures — and handing those to the compiler would ask it
# to build them on their own.
SOURCES = $(filter %.c %.o,$^)

# Whether this build carries the Hysteria2 plane.
#
# Out, lc-tunnel is the REALITY client, 366 387 bytes stripped as packaged; in, it can be either and
# is 786 811 (the packaged figures, measured below), because the plane brings ngtcp2 and nghttp3
# with it. A household uses one node over one protocol,
# so making everybody carry both would be charging most of them for something they never open. The
# two packages are built from this one switch.
HYSTERIA ?= 1

# Header dependencies, tracked by the compiler rather than by hand.
#
# Without this, editing a header rebuilt nothing that included it. That is not a slow build, it is a
# wrong one: a structure that grew by five kilobytes was rebuilt in the library and not in the
# program that declares one on its stack, so the library wrote past the end of it. What that looks
# like from outside is a binary that segfaults before its first line of output, with every source
# file in the tree correct.
DEPFLAGS = -MMD -MP

# Every header in the tree, for the tests: they compile straight from source to an executable, with
# no object file in between for a .d to hang off.
HEADERS = $(shell find src -name '*.h' 2>/dev/null)

# -Werror from the first commit rather than added later: on this target the compiler catches the
# class of mistake otherwise found by a router rebooting in someone's flat.
#
# -Wempty-body is here because its absence cost a live defect: `if (moved > 0 || lan_full)` stood
# over an empty statement in lc-tunnel after a one-line body was deleted, so the following statement
# — the end-of-stream check — silently became the body. Neither -Wall nor -Wextra covers a
# semicolon-free `if` followed by a comment, and nothing else in this set had a reason to speak.
WARN     = -Wall -Wextra -Werror -Wconversion -Wshadow -Wempty-body
# `override`, NOT `?=`, or the hardening is lost without a sound.
#
# `?=` declines to assign when the variable is INHERITED FROM THE ENVIRONMENT, not only when it is
# set in this file. So any invocation shaped like `CFLAGS=-O2 make` — and the OpenWrt SDK exports
# CFLAGS on some paths — would build successfully without `-Werror`, `-D_FORTIFY_SOURCE=2`,
# `-fstack-protector-strong`, `-fno-common` and `-Os`: an unhardened binary indistinguishable from
# outside, and a CI that has stopped going red on new warnings. `override` closes both the command
# line and the environment; the optimisation level can still be changed through EXTRA_CFLAGS, which
# is appended last.
override CFLAGS := -std=c11 -Os $(WARN) -fno-common -fstack-protector-strong -fPIE -pthread
# The language stays strict C11; _GNU_SOURCE only opens the POSIX and Linux declarations the
# socket layer needs — getaddrinfo, clock_gettime, MSG_NOSIGNAL — which ISO C hides. Both glibc and
# musl accept it, and musl is what OpenWrt uses.
# What build this is, stamped into the binary so that the box can be asked instead of remembered.
#
# `--dirty` is the half that matters: a binary built from uncommitted work is the one nobody can
# reconstruct afterwards, and it is also the kind that most often ends up on a router during a long
# afternoon. Falls back to "unknown" outside a checkout, so a source tarball still builds.
LC_VERSION ?= $(shell git describe --always --dirty --tags --abbrev=12 2>/dev/null || echo unknown)

override CFLAGS +=  -DLC_HYSTERIA=$(HYSTERIA) -Isrc -I$(BUILD)/gen -D_GNU_SOURCE -ffunction-sections -fdata-sections  $(DEPFLAGS)
# `+=`, NOT `?=`, and for the reason spelled out one screen above about CFLAGS.
#
# `?=` declines to assign when the variable arrives from the ENVIRONMENT, so an invocation shaped
# like `LDFLAGS=-s make` — and build systems do export LDFLAGS — silently dropped --gc-sections,
# and with it the dead-code elimination this project's size budget is built on. The hardening added
# further down (-pie, -z relro, -z now) survived because it is appended with `+=`; the one line
# that opened the door was this one, sitting directly under the comment explaining why the door
# must stay shut.
LDFLAGS += -Wl,--gc-sections

# Cross-compiling has to be told where mbedTLS is, because the OpenWrt toolchain tarball is a
# compiler and a libc and nothing else. Two things are needed and they come from different places:
#
#   MBEDTLS_INC  the headers, from vendor/mbedtls/include — the same 3.6.6 the device runs.
#   MBEDTLS_LIB  something for the linker to resolve names against. NOT the library off the device:
#                OpenWrt ships it stripped of section headers and ld refuses it ("file in wrong
#                format"). dl/mipslib/stub.c is an empty stub carrying exactly the symbols this
#                program asks for and the right soname, so the NEEDED entry comes out correct and
#                the real library resolves it at run time. See docs/BUILD.md, "Cross-compiling for the router".
#
#     make BUILD=build-mips CC=mipsel-openwrt-linux-gcc \
#          MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB=dl/mipslib
#
# And it is TWO libraries, not one: libz arrived with src/tls/certcomp.c, which opens the compressed
# certificate the hello now asks for. It is not a new dependency on the device: zlib is a base
# package half the system already links, so the router has had it since the first install and this
# costs a NEEDED entry rather than flash. libmbedx509 was a third until 2026-09-30, for
# src/cert/chain.c's chain-and-hostname check, which is now go1.27.1's own (cert/goverify.h). Which also means the cross build needs a stub PER SONAME —
# see docs/BUILD.md, "Cross-compiling for the router".
#
# Named once and used on every link line, including the ones with no certificate anywhere in them.
# The alternative — deciding per binary — is a decision that has to be revisited every time an
# object moves between groups, and the day it is not revisited is a link failure or a missing
# NEEDED. What it costs is an unused entry on a few test binaries, which is nothing on either side.
LC_LIBS = -lmbedcrypto -lz -pthread

MBEDTLS_INC ?=
MBEDTLS_LIB ?=

# And zlib the same way, for the same reason and with the same shape.
#
# src/tls/certcomp.c opens the compressed certificate the hello asks for, and it includes <zlib.h>
# like any C file would. The host has one; the OpenWrt SDK has one in its staging tree; the bare
# toolchain tarball has neither zlib nor any other library header, exactly as it has no mbedTLS. So
# the cross build is told where to look, and the answer is a clone, uncommitted, like every other
# dependency in vendor/ — see docs/BUILD.md.
#
# The alternative, and it was the first thing written here, was to declare `uncompress` by hand and
# skip the header. That compiles everywhere and quietly assumes the width of uLongf and the value of
# Z_OK; a header that is actually read cannot drift from the library that ships beside it.
ZLIB_INC ?=
ifneq ($(ZLIB_INC),)
override CFLAGS +=  -I$(ZLIB_INC)
endif
ifneq ($(MBEDTLS_INC),)
override CFLAGS +=  -I$(MBEDTLS_INC)
endif
ifneq ($(MBEDTLS_LIB),)
LDFLAGS += -L$(MBEDTLS_LIB)
endif

# What another build system adds to ours, rather than replaces.
#
# This exists because the OpenWrt package recipe passed CFLAGS= on the make command line, and a
# variable set there overrides every `+=` in this file — so -Isrc, -D_GNU_SOURCE, -DLC_HYSTERIA and
# the mbedTLS include path all vanished and the package did not compile at all ("core/args.h: No such
# file or directory"). The trap in fixing that by hand is worse than the failure: put -Isrc back and
# the build succeeds with -DLC_HYSTERIA gone, which is a lite-client-hysteria package that installs,
# starts, and has no Hysteria2 plane in it. Additive is the only safe shape, so the SDK's flags come
# in here and nothing of ours is lost.
override CFLAGS +=  $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

# ⚠️ THE COMPILER HALF OF THE HARDENING, AND WHY IT IS DOWN HERE RATHER THAN IN CFLAGS ABOVE.
#
# `-D_FORTIFY_SOURCE=2` used to sit in the base CFLAGS, and that made the package impossible to
# build: OpenWrt hardens at level 1, so TARGET_CFLAGS carries `-D_FORTIFY_SOURCE=1`, it arrives
# through EXTRA_CFLAGS AFTER ours, and gcc says
#
#   <command-line>: error: "_FORTIFY_SOURCE" redefined [-Werror]
#
# — the redefinition is diagnosed at the SDK's flag, so no amount of appending ours later fixes it;
# ours has to not be there yet when the SDK's arrives. Hence `-U` and then the level we want, after
# EXTRA_CFLAGS, which is the same shape and the same reason as the linker hardening below: appended
# last so it survives whatever the SDK contributed.
#
# Level 2 rather than OpenWrt's 1 is a deliberate divergence: this binary is a parser of hostile
# network input, and the reason a distribution picks 1 — one setting applied across thousands of
# packages, where the caution has to be system-wide — does not transfer to a single program. Nothing
# about the router's own packages changes either; the flag is per-compilation.
#
# ⚠️ THE COST OF 2 OVER 1 IS NOW MEASURED, AND THE NUMBER IS LESS INTERESTING THAN WHY IT IS THAT
# NUMBER. Built both ways for mipsel, same tree, same toolchain: the binaries are BYTE-IDENTICAL,
# 857 912 stripped either way. That is not level 2 being free — it is fortify emitting nothing at
# all on this path, because the standalone cross build never puts the fortify headers on the
# include path.
#
# ⛔ AND THE FIRST INSTRUMENT I USED FOR THAT COULD NOT HAVE SEEN IT EITHER WAY. It counted
# `__*_chk` symbols — zero on the device binary, seven on the glibc host build — and read the zero
# as proof. It is not: glibc implements fortify by CALLING `__memcpy_chk` and friends, while
# OpenWrt's fortify-headers for musl inline `__builtin_trap()` at the call site and export no symbol
# at all (13 of them in `string.h` alone). Counting symbols on a musl target measures nothing about
# fortify. The byte-identical pair above is what actually carries this claim, and it still does.
#
# The reason is musl: fortify for it lives in OpenWrt's separate fortify-headers, and they are
# reached only when their directory is on the include path. The standalone cross build below
# (`check-device`) does not add that directory, so on that path the macro is defined and nobody
# reads it — that half IS measured, above.
#
# ⚠️ AND ON THE PACKAGE PATH IT IS ALIVE — counted in the right units this time. Same variant, same
# toolchain, same source, built both ways on 2026-09-11:
#
#     package (hysteria)      99 `break` instructions   872 068 bytes
#     standalone (hysteria)   25                        857 912
#
# `break` is what `__builtin_trap()` becomes on MIPS, so the seventy-four extra ones are bounds
# checks that exist only where the headers are reachable. The SDK is what makes them reachable
# (`TOOLCHAIN_INC_DIRS+= $(TOOLCHAIN_DIR)/include/fortify`, rules.mk:230, under CONFIG_USE_MUSL),
# package/Makefile forwards TARGET_CPPFLAGS into EXTRA_CFLAGS, and the SDK's own
# `-D_FORTIFY_SOURCE=1` is what collided with ours to begin with.
#
# What is still NOT isolated: the two builds differ in more than this flag — TARGET_CFLAGS also
# carries OpenWrt's own optimisation and its stack protector at REGULAR where ours says strong (which
# won then, and since 2026-09-24 no longer does: see the line after fortify's) — so "74 traps" is
# the delta between two builds, not the price of fortify alone. Settling that needs a
# third package build with fortify off, and it has not been run.
#
# ⚠️ SO `check-device` PROVES NOTHING ABOUT THIS LINE. It builds for mipsel and it will stay green
# with any level, or with the flag deleted. What it checks is that the tree compiles for the router;
# the hardening it appears to be covering is only present two paths away. Not closed here because
# closing it means the gate building the .apk, which needs the SDK, and the SDK is fetched rather
# than built — see the package target.
#
# What was measured before and still holds is the size it has to fit in: the packaged binaries are
# 366 387 bytes for the REALITY variant and 786 811 with Hysteria2, both stripped, against the
# "≤ 1.5 MB on flash" docs/DESIGN.md states as the target.
#
# Found only by running the recipe. Every gate in this tree was green the whole time this made the
# package unbuildable, because no gate had ever built the package — "the recipe is written" and "the
# recipe builds" were separate claims and only the first was tested.
override CFLAGS +=  -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2

# And the stack protector again, for the same reason and in the same place. The base CFLAGS say
# `-fstack-protector-strong`, and on the package path TARGET_CFLAGS arrives after it through
# EXTRA_CFLAGS carrying OpenWrt's own `-fstack-protector` — REGULAR — which, being later, is the one
# gcc obeys. Read off the package build's own command line on 2026-09-24: ours eleventh, the SDK's
# thirty-seventh. Regular guards only functions with a character array of eight bytes or more;
# strong guards every function with a local array or an address-taken local, which in a program that
# parses the network into stack buffers is most of the interesting ones. Measured on the package
# build before and after this line, as loads of __stack_chk_fail's GOT slot in the stripped
# lc-tunnel (its offset from `readelf -A`, the loads counted in `objdump -d`): REALITY 55 → 117,
# Hysteria2 87 → 177. The REALITY binary grew by one page, 427 412 → 431 508 bytes; the Hysteria2
# one stayed at 947 320.
override CFLAGS +=  -fstack-protector-strong

# The linker half of the hardening, appended last so it survives whatever the SDK contributed.
#
# Measured rather than assumed, on both artefacts: the host build came out PIE but with only partial
# RELRO, and the mipsel cross-build — the one that reaches a router — came out `Type: EXEC` with no
# GNU_RELRO segment at all. Neither difference was a decision here; the system compiler defaults to
# PIE and the cross-compiler does not, so the binary that gets inspected looked hardened and the
# binary that gets installed was not. `-z now` is what makes RELRO full: without it the GOT stays
# writable for the life of a process whose whole job is parsing hostile input off the network.
#
# NOT `override`, deliberately: that directive makes make ignore every later normal assignment to
# the same variable, and the later ones here are what add -L$(MBEDTLS_LIB) and --gc-sections. Doing
# it that way removed the mbedTLS search path and the cross build stopped linking.
LDFLAGS += -pie -Wl,-z,relro,-z,now

# Tests are built with debug information and without size optimisation: they are never shipped, and
# a readable stack trace is worth more here than a small binary.
#
# _GNU_SOURCE for the same reason the programs have it: the POSIX declarations ISO C hides — open,
# fstat, symlink — are what the code being tested calls, and a test compiled without them fails as
# an implicit declaration rather than as anything to do with the test.
#
# The two decoder include paths are here as well as in CFLAGS because TEST_CFLAGS does not inherit
# from it: src/tls/certcomp.c is compiled straight into test-certcomp, and it asks for
# <brotli/decode.h> and <zstd.h> like any other header.
TEST_CFLAGS = -std=c11 -O1 -g $(WARN) -Isrc -I$(BUILD)/gen -D_GNU_SOURCE \
              -I$(BROTLI_DIR)/c/include -I$(ZSTD_DIR)/lib

# ---- what this tree was last built with --------------------------------------
#
# make rebuilds on a changed FILE and knows nothing about a changed FLAG. The dependency lists the
# compiler writes (-MMD) name headers and nothing else, so `make check` after a change to CFLAGS
# links yesterday's objects against today's and answers a question nobody asked.
#
# Not hypothetical, and not subtle when it lands: a tree built once, then built again with different
# flags, failed at the link with "relocation R_X86_64_32 against `.rodata` can not be used when
# making a PIE object" — stale objects, correct sources. The same shape with -DLC_HYSTERIA or
# -D_FORTIFY_SOURCE would not fail at all; it would produce a binary built half one way and half the
# other, and the gate would call it green.
#
# So the flags are written into a file, that file is rewritten only when they change — `cmp -s`, so
# an unchanged build stays incremental — and every object depends on it.
LC_FLAGS_STAMP = $(BUILD)/gen/flags.stamp
LC_FLAGS_TEXT = $(CC) $(CFLAGS) | $(MLKEM_CFLAGS) | $(LDFLAGS)

.PHONY: FORCE
FORCE:

$(LC_FLAGS_STAMP): FORCE
	@mkdir -p $(dir $@)
	@echo "$(LC_FLAGS_TEXT)" > $@.new
	@cmp -s $@.new $@ || mv $@.new $@
	@rm -f $@.new

# ---- vendored ----------------------------------------------------------------
# mlkem-native is built from source rather than linked as a library: it is a few files of portable
# C90, it needs no build system of its own, and compiling it with our flags means our warnings apply
# to it too.

MLKEM_DIR = vendor/mlkem-native
MLKEM_SRC = $(wildcard $(MLKEM_DIR)/mlkem/src/*.c) $(wildcard $(MLKEM_DIR)/mlkem/src/fips202/*.c)
MLKEM_INC = -I$(MLKEM_DIR)/mlkem -I$(MLKEM_DIR)/mlkem/src
# Warnings are relaxed for vendored code only: it is not ours to fix, and -Werror on someone else's
# sources turns every upstream update into a blocked build.
MLKEM_CFLAGS = -std=c99 -Os -fPIE -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 $(DEPFLAGS) $(MLKEM_INC) \
               -ffunction-sections -fdata-sections
MLKEM_OBJ = $(MLKEM_SRC:%.c=$(BUILD)/%.o)

# cert/chain.c is go1.27.1's x509 underneath — its parser, Certificate.Verify, the signature checks
# and ML-DSA (cert/chain.h) — and this is what a link line that has chain.c needs besides it.
# ML-DSA hashes with mlkem-native's Keccak, so a line without $(MLKEM_SRC) takes that one file, and
# the two -D its header needs to name it (CHAIN_DEFS; harmless where they are already given).
CHAIN_SRC = src/cert/chain.c src/cert/goverify.c src/cert/gosig.c src/cert/x509go.c src/cert/mldsa.c \
            src/reality/url.c src/core/goquote.c src/core/netip.c
CHAIN_KECCAK = $(MLKEM_DIR)/mlkem/src/fips202/keccakf1600.c
CHAIN_DEFS = $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768

$(BUILD)/$(MLKEM_DIR)/%.o: $(MLKEM_DIR)/%.c $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(MLKEM_CFLAGS) -c -o $@ $<

# GHASH, the authentication half of AES-GCM, is the REFERENCE'S algorithm since 2026-09-21: Go's
# generic ghash.go ported line for line into src/tls/ghash.c — see src/tls/ghash.h for which
# reference, why that one, and what a table-driven GHASH gives up. It replaced BearSSL's
# br_ghash_ctmul, which a profile of the live REALITY tunnel on the MT7621 found at 51.6 % of the
# core; on that CPU the reference's algorithm costs 88 ms per MB against ctmul's 172, with the same
# answer on every input tried. vendor/bearssl is no longer compiled into anything.
#
# At -O2 rather than the -Os everything else in src/ gets, for the reason the BearSSL file had it:
# this is the loop a download spends half its processor in, and the byte or two -Os saves here is
# not worth a slower loop. With our own warnings, because unlike the file it replaced it is ours.
GHASH_SRC = src/tls/ghash.c
GHASH_CFLAGS = $(filter-out -Os,$(CFLAGS)) -O2 -ffunction-sections -fdata-sections
GHASH_OBJ = $(BUILD)/src/tls/ghash.o

$(GHASH_OBJ): $(GHASH_SRC) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(GHASH_CFLAGS) -c -o $@ $<

# ChaCha20 and Poly1305, the REFERENCE'S since 2026-09-23: x/crypto's chacha20 and
# internal/poly1305 at the version hysteria resolves, ported into src/tls/chacha.c (four blocks at a
# time in NEON on arm64, as chacha_arm64.s) and src/tls/poly1305.c (sum_generic.go wherever there is
# a 128-bit product; the router's own mbedTLS on MIPS, which has none — poly1305.h says why) — see
# their headers. They replaced mbedTLS's ChaCha20-Poly1305, which on the AX3000T sealed a 1350-byte
# packet in about 35 us where the reference takes 14. At -O2 for the same reason as the GHASH above:
# every byte of that plane passes here.
CHACHA_SRC = src/tls/chacha.c src/tls/poly1305.c
CHACHA_OBJ = $(CHACHA_SRC:%.c=$(BUILD)/%.o)

$(CHACHA_OBJ): $(BUILD)/%.o: %.c $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(GHASH_CFLAGS) -c -o $@ $<

# The other two certificate-compression algorithms, because the fingerprint promises three.
#
# RFC 8879 §4 makes the hello's list a capability, not a wish: a client MUST be able to decompress
# whatever it advertised, and the server picks from that list by ITS OWN preference — measured, not
# assumed: with `zlib, brotli, zstd` offered and zlib written first, all three compressing sites
# answered in brotli. So carrying the reference's list means carrying the reference's decoders.
#
# DECOMPRESSION ONLY, and that is most of what makes the size bearable. brotli's encoder and zstd's
# are not compiled at all — a TLS client never compresses a certificate, it only opens one. What is
# left is 166 KB for brotli (of which 122 KB is the static dictionary, which is data, not code) and
# 77 KB for zstd, measured on mipsel at -Os.
#
# NOT LINKED FROM THE SYSTEM, unlike zlib: an OpenWrt image has libz in its base and neither of
# these. Asking the installer to fetch two more packages onto every box would trade 243 KB of our
# flash for 243 KB of theirs plus a dependency that can fail on a device already short of space.
BROTLI_DIR = vendor/brotli
BROTLI_SRC = $(wildcard $(BROTLI_DIR)/c/common/*.c) $(wildcard $(BROTLI_DIR)/c/dec/*.c)
BROTLI_CFLAGS = -std=c99 -Os -w -fPIE $(DEPFLAGS) -I$(BROTLI_DIR)/c/include \
                -ffunction-sections -fdata-sections
BROTLI_OBJ = $(BROTLI_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/$(BROTLI_DIR)/%.o: $(BROTLI_DIR)/%.c $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(BROTLI_CFLAGS) -c -o $@ $<

# ZSTD_LEGACY_SUPPORT=0 drops the readers for formats zstd itself stopped producing years ago; a
# TLS peer that sent one would be speaking neither RFC 8879 nor zstd as anybody ships it.
# ZSTD_DISABLE_ASM because the tuned paths are x86_64 only and this target is mipsel — left on, the
# build picks up huf_decompress_amd64.S and fails at assembly rather than at configuration.
ZSTD_DIR = vendor/zstd
ZSTD_SRC = $(wildcard $(ZSTD_DIR)/lib/common/*.c) $(wildcard $(ZSTD_DIR)/lib/decompress/*.c)
ZSTD_CFLAGS = -std=c99 -Os -w -fPIE $(DEPFLAGS) -I$(ZSTD_DIR)/lib -I$(ZSTD_DIR)/lib/common \
              -DZSTD_LEGACY_SUPPORT=0 -DZSTD_DISABLE_ASM -ffunction-sections -fdata-sections
ZSTD_OBJ = $(ZSTD_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/$(ZSTD_DIR)/%.o: $(ZSTD_DIR)/%.c $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(ZSTD_CFLAGS) -c -o $@ $<

# Our own certcomp.c includes <brotli/decode.h> and <zstd.h>, and neither header exists on any host
# or in any toolchain tarball — both come from vendor/ always, so unlike ZLIB_INC there is nothing
# to make conditional.
override CFLAGS += -I$(BROTLI_DIR)/c/include -I$(ZSTD_DIR)/lib

# ---- QUIC, for Hysteria2 -----------------------------------------------------
# ngtcp2 and nghttp3 are built from source into our own binary rather than linked from the OpenWrt
# feed. The feed's libngtcp2 ships the core library and its OpenSSL crypto backend in one package
# and declares the dependency for both, so installing it pulls in libopenssl3 — 4 454 KiB against
# 5.3 MiB of free overlay on the target. The core itself needs only libc; the 4.4 MiB is the price
# of exactly the backend src/quic replaces with under four kilobytes.
#
# Their own warnings are not ours to fix, so they build with warnings relaxed. Ours do not.

# ngtcp2 AS BUILT IS THE PINNED UPSTREAM WITH patches/ngtcp2 APPLIED, in a copy under $(BUILD).
#
# vendor/ngtcp2 stays exactly the checkout docs/BUILD.md pins — check-vendor holds it there, and every
# `vendor/ngtcp2/lib/…:line` citation in this tree means that upstream text. What this client needs
# the library to do differently, so that it behaves on the wire as quic-go does, is kept as patches
# in patches/ngtcp2, each saying in its header which reference behaviour it copies. They are applied
# strictly — no fuzz, no offset guessing (`patch -F0`) — so a patch that no longer fits the pinned
# revision stops the build instead of landing somewhere near where it was meant to.
NGTCP2_UPSTREAM = vendor/ngtcp2
NGTCP2_PATCHES = $(sort $(wildcard patches/ngtcp2/*.patch))
NGTCP2_DIR = $(BUILD)/ngtcp2
NGTCP2_STAMP = $(NGTCP2_DIR)/.patched

$(NGTCP2_STAMP): $(NGTCP2_PATCHES) $(wildcard $(NGTCP2_UPSTREAM)/lib/*.[ch] \
                 $(NGTCP2_UPSTREAM)/lib/includes/ngtcp2/*.h $(NGTCP2_UPSTREAM)/crypto/*.[ch] \
                 $(NGTCP2_UPSTREAM)/crypto/includes/ngtcp2/*.h)
	@# Patched in a scratch directory and copied in, stamp last. Every step that edits a file in place
	@# — sed -i, patch — writes a temporary and renames it over the original, and on the Docker Desktop
	@# bind mount this tree is built through, a rename of a file just written is refused now and then
	@# ("Can't rename file lib/ngtcp2_conn.c.o6czusV … Permission denied"). A plain copy only writes.
	@# A failure leaves no stamp, so the next build starts again from nothing.
	@# The sed puts line ends back to what upstream commits: a checkout made with core.autocrlf (a
	@# Windows machine) has CRLF in every file, and the LF patches would not match it.
	@rm -rf $(NGTCP2_DIR)
	@mkdir -p $(NGTCP2_DIR)
	@t=$$(mktemp -d) || exit 1; \
	cp -R $(NGTCP2_UPSTREAM)/lib $(NGTCP2_UPSTREAM)/crypto $$t/ || { rm -rf $$t; exit 1; }; \
	find $$t -type f \( -name '*.c' -o -name '*.h' \) -exec sed -i 's/\r$$//' {} + || { rm -rf $$t; exit 1; }; \
	for p in $(NGTCP2_PATCHES); do \
	    patch -s -p1 -F0 -N -d $$t < $$p \
	        || { echo "$$p does not apply to $(NGTCP2_UPSTREAM) at the pinned revision"; rm -rf $$t; exit 1; }; \
	done; \
	cp -R $$t/lib $$t/crypto $(NGTCP2_DIR)/ || { rm -rf $$t; exit 1; }; \
	rm -rf $$t
	@touch $@

NGHTTP3_DIR = vendor/nghttp3
NGHTTP2_DIR = vendor/nghttp2

# HPACK's static table, taken from the reference rather than typed out.
#
# Sixty-one entries whose ORDER is the protocol: an index IS a position in this list, so one entry
# transposed or dropped shifts every header after it, and the request still encodes — into something
# else. That failure has no symptom on this side at all; it is read by the server. Generated for the
# same reason the fingerprint tables are: a table copied by hand is a table with a mistake in it,
# found later and from further away.
#
# The count is checked rather than trusted. If upstream reformats that array, the pattern below
# stops matching and would otherwise leave a short table — which is the transposition failure again,
# arriving quietly.
# The build's identity, as a header rather than as -D on the command line.
#
# As a -D it was WRONG, and wrong in the way that is worst for a stamp: make has no idea an object
# file depends on the value of a macro, so changing the version rebuilt nothing and the binary kept
# claiming to be the previous commit. Caught the same afternoon it was written, on a router that
# reported `-dirty` after the tree had been committed — a stamp that goes stale by itself is worse
# than none, because it is believed.
#
# As a header it is an ordinary prerequisite and the existing -MMD dependency tracking does the rest.
# Rewritten only when the text differs, so a build that changes nothing recompiles nothing.
$(BUILD)/gen/version.h: FORCE
	@mkdir -p $(dir $@)
	@printf '#define LC_VERSION "%s"\n' '$(LC_VERSION)' > $@.tmp
	@cmp -s $@.tmp $@ || mv $@.tmp $@
	@rm -f $@.tmp

# An empty target that is always out of date, so the recipe above runs every build and decides for
# itself whether anything changed. Nothing else in this file may depend on it.
FORCE:
.PHONY: FORCE

$(BUILD)/gen/hpack_static.h: $(NGHTTP2_DIR)/lib/nghttp2_hd.c
	@mkdir -p $(dir $@)
	@sed -n '/^static const nghttp2_hd_static_entry static_table\[\] = {/,/^};/p' $< \
	  | sed -n 's/.*MAKE_STATIC_ENT(\("[^"]*"\), \("[^"]*"\).*/    { \1, \2 },/p' > $@.tmp
	@n=$$(wc -l < $@.tmp); test "$$n" -eq 61 || { \
	    echo "hpack: expected 61 static entries from $<, got $$n"; rm -f $@.tmp; exit 1; }
	@mv $@.tmp $@

# ⚠️ THE WILDCARD READS THE UPSTREAM TREE, so a file a PATCH adds is not in it and has to be named.
# Patch 0009 adds lib/ngtcp2_hybbr.c — hysteria's congestion control — and without this line it
# would be patched in, never compiled, and the link would fail on ngtcp2_hybbr_init with no hint
# of why. Listing the patched directory instead is not an option: make expands a wildcard before
# the rule that creates the tree has run.
NGTCP2_SRC = $(patsubst $(NGTCP2_UPSTREAM)/%,$(NGTCP2_DIR)/%,\
                  $(wildcard $(NGTCP2_UPSTREAM)/lib/*.c) $(NGTCP2_UPSTREAM)/crypto/shared.c) \
             $(NGTCP2_DIR)/lib/ngtcp2_hybbr.c

# The copied sources exist once the stamp does; this says so to make, which otherwise finds no rule
# for a file that is not there yet when it plans the build. Named one by one rather than as a
# pattern: `$(NGTCP2_DIR)/%.c` claimed that ANY .c there could be made, and make's built-in `%: %.o`
# then chained every dependency file it was asked to include into a compile of `shared.d.c`.
$(NGTCP2_SRC): $(NGTCP2_STAMP) ;
NGHTTP3_SRC = $(wildcard $(NGHTTP3_DIR)/lib/*.c) $(NGHTTP3_DIR)/lib/sfparse/sfparse.c

QUIC_INC = -I$(BUILD)/gen -I$(NGTCP2_DIR)/lib -I$(NGTCP2_DIR)/lib/includes \
           -I$(NGTCP2_DIR)/crypto -I$(NGTCP2_DIR)/crypto/includes \
           -I$(NGHTTP3_DIR)/lib -I$(NGHTTP3_DIR)/lib/includes -I$(NGHTTP3_DIR)/lib/sfparse
# _GNU_SOURCE for both: nghttp3 uses the byte-order functions, which ISO C hides.
# The HAVE_ defines stand in for the cmake config header neither project ships in its tree. They
# only decide which system headers get included; getting one wrong shows up immediately as an
# implicit declaration rather than quietly.
# -fPIE here too, or the link fails: these objects go into the same PIE as ours, and on MIPS an
# R_MIPS_26 relocation from a non-PIC object into a position-independent executable is refused
# outright — which is exactly how this was found.
VENDOR_CFLAGS = -std=c11 -Os -w -fPIE -fno-common -ffunction-sections -fdata-sections -D_GNU_SOURCE -DHAVE_ARPA_INET_H=1 -DHAVE_NETINET_IN_H=1 -DHAVE_UNISTD_H=1 -DHAVE_STDINT_H=1 $(DEPFLAGS)

NGTCP2_OBJ = $(patsubst $(NGTCP2_DIR)/%.c,$(BUILD)/ngtcp2-obj/%.o,$(NGTCP2_SRC))
NGHTTP3_OBJ = $(NGHTTP3_SRC:%.c=$(BUILD)/%.o)

# Both projects generate this from cmake; the two fields in it are the version, and nothing in the
# code branches on them.
$(BUILD)/gen/ngtcp2/version.h: $(NGTCP2_UPSTREAM)/lib/includes/ngtcp2/version.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.15.0/' -e 's/@PACKAGE_VERSION_NUM@/0x010f00/' $< > $@

$(BUILD)/gen/nghttp3/version.h: $(NGHTTP3_DIR)/lib/includes/nghttp3/version.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.11.0/' -e 's/@PACKAGE_VERSION_NUM@/0x010b00/' $< > $@

QUIC_GEN = $(BUILD)/gen/ngtcp2/version.h $(BUILD)/gen/nghttp3/version.h $(NGTCP2_STAMP)

$(BUILD)/ngtcp2-obj/%.o: $(NGTCP2_DIR)/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_CFLAGS) $(QUIC_INC) -c -o $@ $<

$(BUILD)/$(NGHTTP3_DIR)/%.o: $(NGHTTP3_DIR)/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_CFLAGS) $(QUIC_INC) -c -o $@ $<

QUIC_SRC = src/quic/gecko.c src/quic/rxopen.c src/quic/dgram.c src/quic/reasm.c src/quic/udptab.c src/quic/params.c src/quic/rxbuf.c src/quic/txbuf.c src/quic/prefix.c src/quic/qcrypto.c src/quic/qtls.c src/quic/shim.c src/quic/conn.c src/quic/sendq.c src/quic/obfs.c src/quic/gorand.c src/quic/h3.c src/quic/huffman.c src/quic/hy.c src/quic/pad.c src/quic/hop.c src/quic/varint.c src/core/blake2b.c
QUIC_OBJ = $(QUIC_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/src/quic/%.o: src/quic/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(QUIC_INC) -c -o $@ $<

# Builds the whole QUIC stack and reports what it costs, which is the number the two packages exist
# to keep apart. Kept as a target of its own because the cost is worth being able to ask about
# without linking a program around it.
quic: $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ)
	@size -t $^ 2>/dev/null | tail -1 || true

LIB_SRC = src/core/args.c src/core/buf.c src/core/rnd.c src/core/gomap.c src/core/say.c \
          src/core/portunion.c \
          src/fp/fpt.c src/fp/hello.c \
          src/tls/hkdf.c src/tls/prf12.c src/tls/aead.c src/tls/record.c src/tls/recopen.c src/tls/rawin.c src/tls/suite.c \
          src/tls/certverify.c src/tls/ed25519.c src/tls/x25519.c src/tls/fe25519.c src/tls/transcript.c src/tls/kex.c src/tls/msg.c \
          src/cert/cert.c src/cert/chain.c src/tls/certcomp.c src/reality/reality.c \
          src/net/sock.c src/tls/client.c \
          src/net/loop.c src/net/tproxy.c src/net/reader.c src/net/dial.c src/net/goresolve.c \
          src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c \
          src/vless/vless.c src/vless/vision.c src/vless/xudp.c \
          src/quic/qtls.c src/tls/stdmsg.c src/tls/post.c \
          src/cert/x509go.c src/reality/url.c src/core/goquote.c src/core/netip.c \
          src/cert/goverify.c src/cert/gosig.c src/cert/mldsa.c
# The spider, kept OUT of LIB_SRC on purpose.
#
# It is what a REALITY client does when the node did not authenticate it — see reality/spider.h —
# and it needs HTTP/2, which is hpack, the frame layer, Huffman and the prefix integers. Putting it
# in the library would link all of that into lc-hello and lc-probe, which never make a proxied
# connection at all, and into the REALITY-only lc-tunnel, whose smallness on the target is half the
# reason the two packages exist. So it goes to the binaries that reach the path.


H2_SRC = src/h2/xhttp.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/pad.c
H2_OBJ = $(H2_SRC:%.c=$(BUILD)/%.o)
SPIDER_SRC = src/reality/spider.c src/reality/fetch.c src/reality/spider_run.c src/reality/paths.c src/reality/browser.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/core/gozip.c src/quic/gorand.c
SPIDER_OBJ = $(SPIDER_SRC:%.c=$(BUILD)/%.o)

# $(BROTLI_OBJ) and $(ZSTD_OBJ) ride here rather than on the two binaries that complete handshakes,
# for the reason LC_LIBS gives about itself: certcomp.c is in LIB_SRC, so every link line that has
# it needs the decoders, and deciding per binary is a decision somebody forgets to revisit. The
# linker's --gc-sections drops what a given program cannot reach.
LIB_OBJ = $(LIB_SRC:%.c=$(BUILD)/%.o) $(GHASH_OBJ) $(CHACHA_OBJ) $(BROTLI_OBJ) $(ZSTD_OBJ)

HELLO_SRC = src/cmd/lc-hello/main.c
HELLO_OBJ = $(HELLO_SRC:%.c=$(BUILD)/%.o)

PROBE_SRC = src/cmd/lc-probe/main.c
PROBE_OBJ = $(PROBE_SRC:%.c=$(BUILD)/%.o)

FETCH_SRC = src/cmd/lc-fetch/main.c
FETCH_OBJ = $(FETCH_SRC:%.c=$(BUILD)/%.o)

TUNNEL_SRC = src/cmd/lc-tunnel/main.c
TUNNEL_OBJ = $(TUNNEL_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/src/cmd/lc-tunnel/%.o: src/cmd/lc-tunnel/%.c $(QUIC_GEN) $(BUILD)/gen/version.h $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(QUIC_INC) -c -o $@ $<

HY_SRC = src/cmd/lc-hy/main.c
HY_OBJ = $(HY_SRC:%.c=$(BUILD)/%.o)

HYFETCH_SRC = src/cmd/lc-hyfetch/main.c
HYFETCH_OBJ = $(HYFETCH_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/src/cmd/lc-hy/%.o: src/cmd/lc-hy/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(QUIC_INC) -c -o $@ $<

$(BUILD)/src/cmd/lc-hyfetch/%.o: src/cmd/lc-hyfetch/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(QUIC_INC) -c -o $@ $<

HYDNS_SRC = src/cmd/lc-hydns/main.c
HYDNS_OBJ = $(HYDNS_SRC:%.c=$(BUILD)/%.o)

$(BUILD)/src/cmd/lc-hydns/%.o: src/cmd/lc-hydns/%.c $(QUIC_GEN) $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(QUIC_INC) -c -o $@ $<

$(BUILD)/lc-hydns: $(LIB_OBJ) $(HYDNS_OBJ) $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ) $(MLKEM_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# The QUIC probe. It drags in the whole QUIC stack, three hundred and eighty kilobytes the REALITY
# plane has no use for — which is why it is not INSTALLED by the REALITY package, and not a reason to
# leave it out of `all`, where this comment used to claim it was. Building a tool costs the build
# host a few seconds; not building it costs whoever picks it up next a compile error nobody had seen.
$(BUILD)/lc-hy: $(LIB_OBJ) $(HY_OBJ) $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ) $(MLKEM_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# And the one that carries something through it. Built by `all` too, for the same reason.
$(BUILD)/lc-hyfetch: $(LIB_OBJ) $(HYFETCH_OBJ) $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ) $(MLKEM_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# Every tool this repository has, including the three Hysteria2 ones. They were left out, which
# meant nothing built them unless somebody named them by hand — and a tool nobody builds is a tool
# whose compile errors nobody sees. -Werror only helps where it is run.
#
# lc-xfetch is on this line for the same reason and arrived later than the rest: this list said seven
# where the tree had eight, so the XHTTP tool had never been built by anything at all — not by `all`,
# not by `check`, not by the package. Its rule sits at the bottom of this file and was reached only
# by naming the binary by hand, which nobody does twice.
all: $(BUILD)/lc-hello $(BUILD)/lc-probe $(BUILD)/lc-fetch $(BUILD)/lc-tunnel \
     $(BUILD)/lc-hy $(BUILD)/lc-hyfetch $(BUILD)/lc-hydns $(BUILD)/lc-xfetch

$(BUILD)/lc-hello: $(LIB_OBJ) $(HELLO_OBJ) $(MLKEM_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# The probe is the only artefact so far that opens a socket, and the only one that can fail for
# reasons no local test could have caught.
#
# SPIDER_OBJ and H2_OBJ because a probe whose REALITY check FAILS now fetches the masquerade, the
# same as lc-fetch and lc-xfetch: a handshake followed by no application bytes is the one shape a
# REALITY client must not emit, and this is the tool an operator points at a node already under
# suspicion. The comment above the object groups says they go only to the binaries that reach the
# path — this one reaches it.
$(BUILD)/lc-probe: $(LIB_OBJ) $(PROBE_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# The first artefact that carries user traffic rather than merely proving a handshake.
$(BUILD)/lc-fetch: $(LIB_OBJ) $(FETCH_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# What the plane costs, brought in only when it is asked for. Left out, none of these objects reach
# the link line at all — relying on --gc-sections to drop them would work and would still spend the
# time compiling ngtcp2 on every clean build.
ifeq ($(HYSTERIA),1)
TUNNEL_PLANE = $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ)
else
TUNNEL_PLANE =
endif

# The spider and its HTTP/2 come in here as well now: lc-tunnel is the REALITY client that runs in
# the field, so it is the one that most needs to behave like a browser when a node does not know it.
# What that costs on the target is measured in the size table in docs/BUILD.md rather than guessed at.
$(BUILD)/lc-tunnel: $(LIB_OBJ) $(TUNNEL_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)
	@size $@ 2>/dev/null || true

# The white-box cleanup test includes TLS declarations and links target-built
# objects. Keep their include/configuration and PIE flags, then the test flags.
$(BUILD)/test-fetch-cleanup: test/fetch/test_cleanup.c src/reality/fetch.c $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -pthread -o $@ test/fetch/test_cleanup.c $(filter-out $(BUILD)/src/reality/fetch.o,$(sort $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ))) $(LDFLAGS) $(LC_LIBS)

$(BUILD)/gen/header_budget_reference.h: tools/spiderclose/headerbudget/main.go tools/spiderclose/go.mod vendor/x-net/http2/frame.go
	@mkdir -p $(dir $@)
	cd tools/spiderclose && $(GO127) run -mod=readonly ./headerbudget $(abspath $@)

$(BUILD)/test-fetch: $(BUILD)/gen/header_budget_reference.h

$(BUILD)/test-headerbudget: test/fetch/test_headerbudget.c src/reality/fetch.c $(BUILD)/gen/header_budget_reference.h $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -pthread -o $@ test/fetch/test_headerbudget.c $(filter-out $(BUILD)/src/reality/fetch.o,$(sort $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ))) $(LDFLAGS) $(LC_LIBS)

$(BUILD)/test-vision-io: test/vision/test_io.c src/cmd/lc-tunnel/main.c $(BUILD)/gen/version.h $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -ULC_HYSTERIA -DLC_HYSTERIA=0 -pthread -o $@ test/vision/test_io.c $(sort $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)) $(LDFLAGS) $(LC_LIBS)

$(BUILD)/gen/vision_close_reference.h: tools/visionclose/main.go vendor/Xray-core/go.mod vendor/Xray-core/proxy/proxy.go
	@mkdir -p $(dir $@)
	cd vendor/Xray-core && CGO_ENABLED=0 $(GO127) run -mod=readonly ../../tools/visionclose/main.go $(abspath $@)

$(BUILD)/test-vision-close: test/vision/test_close.c src/cmd/lc-tunnel/main.c $(BUILD)/gen/version.h $(BUILD)/gen/vision_close_reference.h $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -ULC_HYSTERIA -DLC_HYSTERIA=0 -pthread -o $@ test/vision/test_close.c $(sort $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)) $(LDFLAGS) $(LC_LIBS)

# Optional paired oracle: real pinned Go transport, controlled channel barriers,
# and the C production drivers. The C cases also run in the ordinary check suite.
.PHONY: check-spider-close
check-spider-close: $(BUILD)/test-fetch-cleanup $(BUILD)/test-fetch
	$(BUILD)/test-fetch-cleanup --close-oracle > $(BUILD)/spider-close-c.log
	$(BUILD)/test-fetch > $(BUILD)/spider-flow-c.log
	cd tools/spiderclose && $(GO127) test -mod=readonly -count=1 -v -timeout=30s . -c-log $(abspath $(BUILD))/spider-close-c.log -flow-log $(abspath $(BUILD))/spider-flow-c.log > $(abspath $(BUILD))/spider-close-go.log
	@cat $(BUILD)/spider-close-go.log

# Correctness/lifetime tests and the controlled Go close oracle are required;
# matching scheduler-dependent CANCEL/path frequencies is not a gate.
.PHONY: check-spider-behavior check-checkpoint-analysis
check-spider-behavior: check
	$(MAKE) --no-print-directory check-spider-close

check-checkpoint-analysis:
	sh -n tools/vendorcap/nativeclient/native-device.sh
	sh -n tools/vendorcap/nativeclient/native-policy-soak.sh
	sh -n tools/vendorcap/nativeclient/native-lan.sh
	$(PYTHON) -m unittest discover -s tools/vendorcap/nativeclient -p 'test_*.py'

# Actual tunnel socket/TLS handoff under forced EAGAIN; unused program sections are discarded.
$(BUILD)/test-spider-tunnel: test/fetch/test_tunnel.c src/cmd/lc-tunnel/main.c $(BUILD)/gen/version.h $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(QUIC_INC) -pthread -o $@ test/fetch/test_tunnel.c $(sort $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)) $(LDFLAGS) $(LC_LIBS)

$(BUILD)/test-hy-tunnel: test/hy/test_tunnel.c src/cmd/lc-tunnel/main.c $(BUILD)/gen/version.h $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(QUIC_INC) -pthread -o $@ test/hy/test_tunnel.c $(sort $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)) $(LDFLAGS) $(LC_LIBS)

# Optional native observation; compile tunnel/task code with ordinary client flags.
$(BUILD)/bench-spider-workers: test/bench/bench_spider_workers.c src/cmd/lc-tunnel/main.c $(HEADERS) $(BUILD)/gen/version.h $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)
	$(CC) $(CFLAGS) $(QUIC_INC) -pthread -o $@ test/bench/bench_spider_workers.c $(sort $(LIB_OBJ) $(TUNNEL_PLANE) $(MLKEM_OBJ) $(SPIDER_OBJ) $(H2_OBJ)) $(LDFLAGS) $(LC_LIBS)

$(BUILD)/%.o: %.c $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -c -o $@ $<

# ---- generated ---------------------------------------------------------------
# RFC 8448 prints every input and output of the TLS 1.3 key schedule. Transcribing those by hand is
# how a typo ends up in a test that then passes on wrong code, so they are extracted from the
# document itself, and the document is kept alongside the extractor.

$(BUILD)/gen/test_vectors.h: tools/vectors/extract.awk tools/vectors/rfc8448.txt
	@mkdir -p $(dir $@)
	awk -f tools/vectors/extract.awk tools/vectors/rfc8448.txt > $@

# ML-KEM vectors come from Go's crypto/mlkem — the implementation on the other end of the wire.
# mlkem-native's own known-answer tests would only prove it agrees with itself.
$(BUILD)/gen/mlkem_vectors.h: tools/mlkem/main.go
	@mkdir -p $(dir $@)
	cd tools/mlkem && go run . > $(abspath $@)

# Certificates come from Go too, including one shaped the way a REALITY server sends them.
$(BUILD)/gen/cert_vectors.h: tools/cert/main.go
	@mkdir -p $(dir $@)
	cd tools/cert && go run . > $(abspath $@)

# What quic-go computes, run from quic-go: the packet-number length, the long header, the
# connection IDs a client moves through, the receive windows, NewReno and its pacer, loss detection
# and the RTT estimate. The generators are laid into vendor/quic-go through `go test -overlay` and
# nothing under vendor/ is written; see tools/qgovec/gen.sh. test/ngpatch and test/hybbr replay them
# on the patched ngtcp2.
QGOVEC_SRC = $(wildcard tools/qgovec/*.go) tools/qgovec/gen.sh \
             $(wildcard vendor/quic-go/internal/congestion/*.go vendor/quic-go/internal/protocol/*.go \
                        vendor/quic-go/internal/wire/*.go vendor/quic-go/internal/utils/*.go \
                        vendor/quic-go/internal/ackhandler/*.go) \
             vendor/quic-go/conn_id_manager.go $(wildcard vendor/quic-go/flow_controller_*.go) \
             vendor/quic-go/crypto_stream.go vendor/quic-go/frame_sorter.go vendor/quic-go/sni.go \
             $(wildcard vendor/quic-go/streams_map_*going.go)
$(BUILD)/gen/qgo_vectors.h: $(QGOVEC_SRC)
	@mkdir -p $(dir $@)
	sh tools/qgovec/gen.sh $@

$(BUILD)/gen/trust_anchors.h: tools/qgovec/trustanchors.sh tools/qgovec/trustanchors_test.go vendor/quic-go/internal/handshake/chrome_client_hello.go
	@mkdir -p $(dir $@)
	sh tools/qgovec/trustanchors.sh $@

# Where each key lands when Go walks a fresh map, measured from Go's own maps — what core/gomap is
# held to. See tools/gomap/main.go.
$(BUILD)/gen/gomap_vectors.h: tools/gomap/main.go
	@mkdir -p $(dir $@)
	cd tools/gomap && go run . > $(abspath $@)

# The Go map walk, emulated, against the measurement. Links its own lc_rnd — a fast generator —
# because a quarter of a billion inserts through a syscall each would take minutes; the model is
# what is under test. It includes src/core/gomap.c, to see the tables behind the walk.
$(BUILD)/test-gomap: test/gomap/test_gomap.c src/core/gomap.c $(BUILD)/gen/gomap_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/gomap/test_gomap.c -lm

# Real signatures over the real signing input, made by Go. The negative cases in test/certverify are
# passed by a verifier that always refuses; these are what make the suite mean something.
$(BUILD)/gen/certverify_vectors.h: tools/certverify/main.go
	@mkdir -p $(dir $@)
	cd tools/certverify && go run . > $(abspath $@)

$(BUILD)/gen/mldsacv_vectors.h: tools/mldsacv/main.go tools/mldsacv/go.mod
	@mkdir -p $(dir $@)
	cd tools/mldsacv && $(GO127) run . > $(abspath $@)

# A root, an intermediate and four leaves: the store the stranger path is checked against, and the
# certificates that do or do not reach it. Go's x509 makes them, because Go's x509 is what the
# reference would have been asking.
$(BUILD)/gen/chain_vectors.h: tools/chain/main.go
	@mkdir -p $(dir $@)
	cd tools/chain && go run . > $(abspath $@)

# The brotli and zstd vectors, from the encoders in the same vendored trees. Go's standard library
# has neither and `make check` runs with --network none, so a Go generator would need modules it
# cannot fetch — see the header of tools/certcomp/gen.c.
#
# $(HOSTCC), not $(CC): this program RUNS at build time. Compiled with the cross compiler during a
# device build it would produce a mipsel binary the build host cannot execute, and the failure would
# arrive as an exec format error inside a rule that looks like it only writes a header.
HOSTCC ?= cc
$(BUILD)/gen/certcomp_vectors.h: tools/certcomp/gen.c $(BUILD)/gen/chain_vectors.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -O1 -w -I$(BUILD)/gen -I$(BROTLI_DIR)/c/include \
	    -I$(ZSTD_DIR)/lib -I$(ZSTD_DIR)/lib/common -DZSTD_LEGACY_SUPPORT=0 -DZSTD_DISABLE_ASM \
	    -o $(BUILD)/gen-certcomp tools/certcomp/gen.c \
	    $(wildcard $(BROTLI_DIR)/c/common/*.c) $(wildcard $(BROTLI_DIR)/c/enc/*.c) \
	    $(wildcard $(ZSTD_DIR)/lib/common/*.c) $(wildcard $(ZSTD_DIR)/lib/compress/*.c) -lm
	$(BUILD)/gen-certcomp > $@

# The REALITY reference is transcribed from Xray and the REALITY server, not paraphrased.
$(BUILD)/gen/reality_vectors.h: tools/reality/main.go vendor/Xray-core/core/core.go
	@mkdir -p $(dir $@)
	cd tools/reality && go run . > $(abspath $@)


# ---- the fingerprint table the REALITY plane is started with ------------------
#
# lc-tunnel takes this as its first argument, and until now nothing in the tree produced it: the
# name appeared in the service script that requires it and nowhere else, so a packaged REALITY
# plane could not start on a router nobody had visited by hand.
#
# THE FIREFOX TABLE IS A DETERMINISTIC FUNCTION OF THE PINNED uTLS AGAIN, WHICH IS WHY IT IS GATED.
#
# The profile has to be named. Measured at twelve regenerations each, `firefox` once gave ONE table
# and `chrome` TWELVE DIFFERENT ONES, because chrome shuffles its extension order per hello and a
# capture froze the order it saw, and its inline GREASE with it. Both are gone from the table — the
# order is the parrot's literal one and GREASE is folded — so chrome is gated as firefox is; see the
# note above fp_capture.
#
# This said the opposite, and it was true when it was written: twelve captures of `firefox` gave two
# distinct tables differing in ONE byte, the ECH GREASE AEAD identifier, because the packer read that
# field off the RENDERED hello and uTLS draws it per hello (`randomly picked from
# CandidateCipherSuites`, vendor/utls/u_ech.go:48) — twelve came out eight to four. That is no longer
# how the field is obtained. Since the GREASE-ECH record grew to carry the whole candidate list,
# tools/fp reads the list off the PARROT (echParrot in tools/fp/main.go) precisely because
# reading the drawn value was the defect, and no drawn value reaches the table at all.
#
# Measured the same way the old claim was, and that is the only reason it is stated: twelve
# regenerations inside the check container with `--network none` produced ONE table, byte for byte
# the shipped one. So the reason not to compare is gone, and the thing it was covering for is not —
# see check-fingerprint.
#
# Every .go file, not the three that used to be named here. build.go renders the GREASE-ECH extension
# and names.go carries the profile list, and neither was a prerequisite: editing the packer left the
# binary on disk untouched, so the next regeneration ran yesterday's code. Harmless while nothing
# compared the output; with the gate below it would make a stale tool a wrong ANSWER.
$(BUILD)/fp: $(wildcard tools/fp/*.go) tools/fp/go.mod tools/fp/go.sum
	@mkdir -p $(dir $@)
	cd tools/fp && $(GO127) build -o $(abspath $@) .

# Shared encoder source, independent reference dependencies and toolchain.
$(BUILD)/fp-hysteria: $(wildcard tools/fp/*.go) tools/fp/hysteria.mod tools/fp/hysteria.sum
	@mkdir -p $(dir $@)
	cd tools/fp && go build -mod=readonly -modfile=hysteria.mod -o $(abspath $@) .

# ⚠️ THE CAPTURE IS SPELLED ONCE, AND check-fingerprint MAKES ITS TABLE WITH THIS SPELLING.
#
# That gate's whole claim is "the shipped table is what today's uTLS produces", and it answers it by
# building a table and comparing byte for byte. Built a DIFFERENT way — another profile, another
# placeholder SNI — it is comparing the answers to two different questions: it reports a drift that
# is its own, or stays quiet about one that is not. Two callers, one definition.
#
# $(1) is the .fpt to write, $(2) a scratch prefix for the intermediate capture.
#
# The SNI is a placeholder and nothing more: the table stores server_name as a MODE, and the name is
# substituted when the hello is built — see LC_FPT_SNI. What it must not be is empty, since the
# capture has to contain the extension for the table to record it. It is given to `table` as well as
# to `dump`, because the packer renders a parrot of its own to read the ECH candidate list off — it
# used to carry the same placeholder as a literal in tools/fp/table.go, which was a third spelling
# of this line in a file nobody editing this one would open.
#
# $(3) is the profile. The shipped table is firefox; test/fphello/chrome.fpt is chrome, the profile
# Xray's "chrome" names and the one a router configured for it runs.
#
# ⚠️ A SHUFFLING PROFILE IS GATED NOW TOO, which the note above $(BUILD)/fp said could not be done. It
# could not while the table kept the order its capture drew and the inline GREASE its capture drew.
# tools/fp now stores Chrome in its parrot's LITERAL order, read out of the uTLS source this very
# binary links (`-parrots`, tools/fp/order.go), and folds inline GREASE onto the placeholder, so a
# Chrome table is the same bytes on every regeneration — measured six times in the check container.
# The literal order is not a convenience: the client's shuffle is the reference's skip-based loop,
# and that loop's law depends on where it starts.
#
# FP_PARROTS is asked of Go rather than written down, for the reason every pin here is: the file has
# to be the one inside the module go.mod pins, and `go list -m` is what knows where that is.
FP_SNI     = www.avito.ru
FP_PARROTS = $$(cd tools/fp && $(GO127) list -m -f '{{.Dir}}' github.com/refraction-networking/utls)/u_parrots.go
FP_HYSTERIA_PARROTS = $$(cd tools/fp && go list -modfile=hysteria.mod -m -f '{{.Dir}}' github.com/refraction-networking/utls)/u_parrots.go
fp_capture = $(BUILD)/fp dump -fp $(3) -sni $(FP_SNI) -o $(2).bin && \
             $(BUILD)/fp table -o $(1) -format bin -name $(3) -sni $(FP_SNI) -parrots $(FP_PARROTS) $(2).bin

package/files/fingerprint.fpt: $(BUILD)/fp
	$(call fp_capture,$@,$(BUILD)/fp-ref,firefox)

test/fphello/chrome.fpt: $(BUILD)/fp
	$(call fp_capture,$@,$(BUILD)/fp-chrome,chrome)

# THE HYSTERIA2 PLANE'S HELLO, which is not one of uTLS's presets and not the API's to send.
#
# From hysteria 2.11 the client parrots Chrome's QUIC stack by default, and its ClientHello comes
# from the fork's own spec, chromeQUICClientHelloSpec, run through a uTLS QUIC connection
# (vendor/quic-go/internal/handshake/tls_conn_utls.go:33-45). tools/fp renders it the same way
# (tools/fp/quic.go) and packs it like any other table, except that quic_transport_parameters is a
# mode — the transport writes that body — and that the table is compiled in, as a C array: every
# Hysteria2 client sends this hello, whatever node it dials. The spec is a COPY, since the fork keeps
# it in an internal package; `fp speccheck` in check-fingerprint holds it to the fork's text.
#
# Hysteria's generator links the fork's own uTLS v1.8.2 through hysteria.mod.
# Its source is shared with fp; its dependency graph and Go toolchain are not.
QUIC_SPEC = vendor/quic-go/internal/handshake/chrome_client_hello.go
fp_capture_quic = $(BUILD)/fp-hysteria dump -fp chrome-quic -sni $(FP_SNI) -o $(2).bin && \
                  $(BUILD)/fp-hysteria table -o $(1) -format c -symbol lc_chrome_hello_fpt -name chrome-quic \
                      -sni $(FP_SNI) -parrots $(FP_HYSTERIA_PARROTS) -spec $(QUIC_SPEC) $(2).bin

# ⚠️ A TARGET OF ITS OWN, NOT A RULE FOR THE HEADER. The header is compiled into every build, the
# router's included, and while it was the target of a rule whose prerequisite is a HOST tool, every
# build that compiled it had to have $(BUILD)/fp first: check-device went to build tools/fp with
# the router's gcc as cgo's compiler and stopped on `-m64` (2026-09-26). And a host build regenerated
# it whenever the tool was newer than the file — so on a fresh tree the cmp in check-fingerprint
# compared the header with a copy of itself. It is written only when asked, like the two tables
# above, and check-fingerprint renders its own copy to compare.
.PHONY: chrome-hello
chrome-hello: $(BUILD)/fp-hysteria $(QUIC_SPEC)
	$(call fp_capture_quic,src/quic/chrome_hello.h,$(BUILD)/fp-cq)

.PHONY: fingerprint
fingerprint: package/files/fingerprint.fpt test/fphello/chrome.fpt chrome-hello

# ---- the OpenWrt package ------------------------------------------------------
#
# package/Makefile had been in the tree since August and had never been run once. It is not a sketch
# — two variants, conffiles, the fingerprint table as a build input, the version stamp worked out in
# $(CURDIR) — but "the recipe is written" and "the recipe builds" are different claims, and only the
# first was ever true. The first real run found `_FORTIFY_SOURCE redefined` (see the flag comment
# above) and the recipe's own premise being false: a bare SDK does NOT carry mbedTLS headers.
#
# The SDK is fetched, not built, so it lives in dl/ beside the cross toolchains, with its checksum
# pinned here the way docker/Dockerfile pins Go's. It is 219 MB; `make clean` must never touch it.
OPENWRT_RELEASE = 25.12.5
SDK_NAME        = openwrt-sdk-$(OPENWRT_RELEASE)-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64
SDK_SHA256      = 9962084f4131610e90e48bc864c6ceade0b238f15f335de5f672910532b20e9c
SDK_URL = https://downloads.openwrt.org/releases/$(OPENWRT_RELEASE)/targets/ramips/mt7621/$(SDK_NAME).tar.zst

# ⚠️ AND THE CHECKSUM DECIDES WHETHER THE FILE EXISTS, NOT JUST WHETHER THE RECIPE PRINTED.
#
# curl writing straight onto $@ leaves the rejected 219 MB behind when sha256sum refuses it, and
# there is no .DELETE_ON_ERROR in this file: the next run finds the target present, calls it up to
# date, and `sdk-fetch` reports success over the very bytes it refused once. So the download lands
# beside the target and is renamed only after the check passes, and the partial is removed so that
# a retry is a retry. Same rule as write_file_atomic on the routers, for the same reason.
dl/$(SDK_NAME).tar.zst:
	@mkdir -p dl
	curl -fL -o $@.part $(SDK_URL)
	@echo "$(SDK_SHA256)  $@.part" | sha256sum -c - || { rm -f $@.part; exit 1; }
	@mv $@.part $@

.PHONY: sdk-fetch
sdk-fetch: dl/$(SDK_NAME).tar.zst

AARCH64_SDK_NAME = openwrt-sdk-$(OPENWRT_RELEASE)-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
AARCH64_SDK_SHA256 = ff4a38a397caa2cfe1c39e18f84ddede14878221b3593c3f2c4cfe24e3ec4c25
AARCH64_SDK_URL = https://downloads.openwrt.org/releases/$(OPENWRT_RELEASE)/targets/mediatek/filogic/$(AARCH64_SDK_NAME).tar.zst

dl/$(AARCH64_SDK_NAME).tar.zst:
	@mkdir -p dl
	curl -fL -o $@.part $(AARCH64_SDK_URL)
	@echo "$(AARCH64_SDK_SHA256)  $@.part" | sha256sum -c - || { rm -f $@.part; exit 1; }
	@mv $@.part $@

.PHONY: sdk-fetch-aarch64
sdk-fetch-aarch64: dl/$(AARCH64_SDK_NAME).tar.zst
	@echo "$(AARCH64_SDK_SHA256)  $<" | sha256sum -c -

# ---- the cross toolchains ------------------------------------------------------
#
# check-device and check-arm64 refuse to pass without them, and until 2026-09-24 nothing said where
# they come from: dl/ is gitignored, the tarballs had been fetched by hand in August, and a fresh
# clone had no recipe, no URL and no checksum to reach the state the gate demands. Fetched and pinned
# the way the SDK is, from the same release: mipsel for MT7621 into dl/tc, aarch64 for the AX3000T
# (mediatek/filogic) into dl/tc-a64. The two checksums are the release's own sha256sums, and they
# are what the tarballs in use since August hash to.
#
# The directories are the targets and they fetch their tarball themselves, rather than depending on
# it: a toolchain unpacked by hand has no tarball beside it under this name, and a prerequisite that
# is missing is a prerequisite make goes and downloads — 117 MB to reproduce what is already there.
TC_NAME       = openwrt-toolchain-$(OPENWRT_RELEASE)-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64
TC_SHA256     = 04316e081dcaea0394d3a8eca761500c91d7d54e9d49ccb8f855ae257ea4f995
TC_A64_NAME   = openwrt-toolchain-$(OPENWRT_RELEASE)-mediatek-filogic_gcc-14.3.0_musl.Linux-x86_64
TC_A64_SHA256 = 39d1965bb6307e70a3b78847bb043dff6ea6e6b4b139b27e75bb003c3c7abf74
TC_BASE       = https://downloads.openwrt.org/releases/$(OPENWRT_RELEASE)/targets

# Same shape as the SDK's: land beside the target, check, rename — see the ⚠️ over that rule.
dl/$(TC_NAME).tar.zst:
	@mkdir -p dl
	curl -fL -o $@.part $(TC_BASE)/ramips/mt7621/$(TC_NAME).tar.zst
	@echo "$(TC_SHA256)  $@.part" | sha256sum -c - || { rm -f $@.part; exit 1; }
	@mv $@.part $@

dl/$(TC_A64_NAME).tar.zst:
	@mkdir -p dl
	curl -fL -o $@.part $(TC_BASE)/mediatek/filogic/$(TC_A64_NAME).tar.zst
	@echo "$(TC_A64_SHA256)  $@.part" | sha256sum -c - || { rm -f $@.part; exit 1; }
	@mv $@.part $@

dl/tc/$(TC_NAME):
	@$(MAKE) --no-print-directory dl/$(TC_NAME).tar.zst
	@mkdir -p dl/tc
	tar --zstd -xf dl/$(TC_NAME).tar.zst -C dl/tc

dl/tc-a64/$(TC_A64_NAME):
	@$(MAKE) --no-print-directory dl/$(TC_A64_NAME).tar.zst
	@mkdir -p dl/tc-a64
	tar --zstd -xf dl/$(TC_A64_NAME).tar.zst -C dl/tc-a64

.PHONY: tc-fetch
tc-fetch: dl/tc/$(TC_NAME) dl/tc-a64/$(TC_A64_NAME)

# ⚠️ SDK_DIR IS NOT UNDER dl/, AND THAT IS NOT A PREFERENCE.
#
# OpenWrt refuses to build on a case-insensitive filesystem — "Build dependency: OpenWrt can only be
# built on a case-sensitive filesystem", and it is right to refuse. A Docker bind mount of an NTFS
# working copy is exactly that, so unpacking the SDK into the tree produces a build that cannot
# start; `FORCE=1` would silence a check that exists for a reason. It also costs: unpacking into the
# bind mount took 3 m 56 s against 5.4 s into a container volume, 44 times slower for 1.1 GB of small
# files. So the SDK is unpacked into a volume and named here, and only the tarball lives in dl/.
#
# Two things the recipe needs that a bare SDK does not have, both learned by running it:
#   * the base feed — libmbedtls, zlib, ca-bundle and ip-full are NOT in the SDK, which ships only
#     package/kernel and package/toolchain. Without them the build dies on
#     `mbedtls/platform_util.h: No such file or directory`, which reads as a missing dependency of
#     ours and is a missing FEED. `./scripts/feeds update base && ./scripts/feeds install ...`
#     needs the network once; the build itself does not afterwards.
#   * a non-root user — OpenWrt declines to build as root.
#
# And `clean` is not optional when this tree changed: Build/Prepare copies src, vendor, tools and
# this Makefile into PKG_BUILD_DIR ONCE, guarded by a .prepared stamp, so editing a source file and
# rebuilding silently compiles yesterday's copy. Cost one confused rebuild here; the same shape as
# the .d files that do not record CFLAGS.
SDK_DIR ?= /sdk/$(SDK_NAME)

.PHONY: package
# ⚠️ NO PREREQUISITE ON THE TABLE, AND THAT IS WHAT MAKES THE DOCUMENTED ORDER WORK AT ALL.
#
# It used to be `package: package/files/fingerprint.fpt`, so any run where $(BUILD)/fp came out newer
# than the committed table made this target REGENERATE it — as the `build` user, because OpenWrt
# refuses to build as root. Every other documented flow here runs as root and shares build/ through
# the same bind mount, so the ordinary sequence docs/BUILD.md prints — `make check`, then `make package` —
# died on
#
#   error: open build/fp-ref.bin: permission denied
#
# Measured on 2026-09-11: `make check` left build/fp newer than the table, and the package build
# could not write beside it.
#
# ⚠️ ORDER-ONLY (`| package/files/fingerprint.fpt`) DOES NOT FIX THIS, and I tried it first. The pipe
# only stops the prerequisite's timestamp from making the TARGET out of date; make still brings the
# prerequisite itself up to date, runs its rule, and fails in exactly the same place. Verified by
# running it — `make -d` says "Prerequisite 'build/fp' is newer ... Must remake target" with the pipe
# in place. The rule has to not be reachable from here at all.
#
# What this target needs is that the table EXISTS. Whether it is CURRENT is a different question with
# its own owner: check-fingerprint regenerates and compares byte for byte, and it is in check-builds.
# `make fingerprint` is how a person asks for a new one, deliberately and as themselves.
package:
	@test -f package/files/fingerprint.fpt || { echo "  FAIL  package/files/fingerprint.fpt is missing — run \`make fingerprint\` first"; exit 1; }
	@test -d "$(SDK_DIR)" || { echo "  FAIL  no unpacked SDK at $(SDK_DIR) — see docs/BUILD.md, 'The OpenWrt package'"; exit 1; }
	ln -sfn $(CURDIR)/package $(SDK_DIR)/package/lite-client
	$(MAKE) -C $(SDK_DIR) package/lite-client/clean
	$(MAKE) -C $(SDK_DIR) package/lite-client/compile
	@find $(SDK_DIR)/bin -name 'lite-client*.apk' -printf '  %10s  %p\n'

# Explicit SDK qualification, kept outside the standard host/cross gate.
# Use a fresh BUILD path: receipts and disposable roots must not overwrite an earlier run.
.PHONY: check-package
check-package: package
	$(PYTHON) test/config/check_apk.py --sdk "$(SDK_DIR)" --output "$(abspath $(BUILD)/package-check)"
	$(PYTHON) test/config/check_service.py --rc-common "$(SDK_DIR)/feeds/base_root/package/base-files/files/etc/rc.common" --output "$(abspath $(BUILD)/service-check)"

# ---- tests -------------------------------------------------------------------
# mbedTLS supplies SHA-2 and HMAC here exactly as it will on the device, where it already sits on
# the flash of every OpenWrt image.

$(BUILD)/test-hkdf: test/hkdf/test_hkdf.c src/tls/hkdf.c $(BUILD)/gen/test_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# The AEAD itself, against the implementation it replaced. mbedTLS's GCM and ChaCha20-Poly1305
# headers are included by the test rather than by src/tls/aead.c: nothing in the client calls either
# any more, and the only reason to reach for them is to have the replaced code compute the answer
# during the check.
$(BUILD)/test-aead: test/aead/test_aead.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# THE SAME SUITE WITH THE MIPS ROUTERS' Poly1305, for the reason test-x25519-ref10 exists: this host
# has a 128-bit product and so computes Go's form, the routers do not and hand it to mbedTLS (see
# src/tls/poly1305.h), and without this the path every mipsel binary ships with would be compiled by
# check-device and never executed.
$(BUILD)/test-aead-mbedpoly: test/aead/test_aead.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -DLC_POLY1305_MBEDTLS -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-record: test/record/test_record.c src/tls/record.c src/tls/suite.c src/core/rnd.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC) $(BUILD)/gen/test_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-handshake: test/handshake/test_handshake.c src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c \
                         src/core/rnd.c src/tls/hkdf.c $(BUILD)/gen/test_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# $(MLKEM_SRC) is a prerequisite as well as a source. It was named only on the command line, so a
# change inside the vendored implementation this test exists to check did not rebuild the test.
$(BUILD)/test-mlkem: test/mlkem/test_mlkem.c src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c \
                     src/core/rnd.c $(MLKEM_SRC) $(BUILD)/gen/mlkem_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -o $@ \
	    $(SOURCES) $(LC_LIBS)

$(BUILD)/test-msg: test/msg/test_msg.c src/tls/msg.c src/tls/transcript.c src/tls/hkdf.c \
                   src/cert/cert.c $(CHAIN_SRC) $(CHAIN_KECCAK) $(BUILD)/gen/test_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ $(SOURCES) $(LC_LIBS)

# What the REALITY plane makes of the node's records once the handshake is over, held to what the
# reference did in front of tools/vendorcap/nodealert.
$(BUILD)/test-post: test/post/test_post.c src/tls/post.c src/tls/stdmsg.c src/tls/msg.c \
                    src/tls/transcript.c src/tls/hkdf.c src/cert/cert.c $(CHAIN_SRC) $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-args: test/args/test_args.c src/core/args.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

# The clamp that every log line in this tree now goes through. Linked against nothing but say.c:
# the point of the suite is that this one function is right, not that a caller of it is.
$(BUILD)/test-say: test/say/test_say.c src/core/say.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

$(BUILD)/test-cert: test/cert/test_cert.c test/cert/remarshal_vectors.h src/cert/cert.c $(CHAIN_SRC) $(CHAIN_KECCAK) src/tls/msg.c src/tls/hkdf.c \
                    $(BUILD)/gen/cert_vectors.h $(BUILD)/gen/test_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ $(SOURCES) $(LC_LIBS)

# Three algorithms, three vectors, and they are not equally strong: the zlib stream is written by Go
# — an implementation independent of the libz that opens it — while brotli and zstd come from the
# encoders in the same vendored trees as their decoders. The header of test_certcomp.c says what
# that does and does not prove.
$(BUILD)/test-certcomp: test/certcomp/test_certcomp.c test/certcomp/reference_open.h src/tls/certcomp.c \
                        $(BROTLI_OBJ) $(ZSTD_OBJ) \
                        $(BUILD)/gen/chain_vectors.h $(BUILD)/gen/certcomp_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# No mbedTLS stand-in and no fixture of a verdict: the verifier under test is the one that runs on
# the router, asking the library the router has. What the test controls is the store it asks against.
$(BUILD)/test-chain: test/chain/test_chain.c $(CHAIN_SRC) $(CHAIN_KECCAK) src/cert/cert.c \
                     $(BUILD)/gen/chain_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-reality: test/reality/test_reality.c src/reality/reality.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c \
                       src/tls/hkdf.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC) src/core/rnd.c $(BUILD)/gen/reality_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# The GREASE rules are checked against a table built inside the test, so this one needs no capture,
# no network and no generated fixture.
$(BUILD)/test-hello: test/hello/test_hello.c src/fp/hello.c src/fp/fpt.c src/core/rnd.c src/core/buf.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# THE GO THE XRAY REFERENCE IS BUILT WITH, 1.27 (vendor/Xray-core/go.mod:3), for the generators that
# stand for it: under it the spider's HTTP/2 client is net/http's own, and its IDNA, httpguts,
# net/url and redirect rules are that Go's standard library. The build image carries it beside the
# 1.26 the hysteria reference is built with (docker/Dockerfile); a tool whose go.mod says `go 1.27`
# runs with it.
GO127 ?= /usr/local/go1.27/bin/go

# golang.org/x/text and golang.org/x/net as Go 1.27 ships them (GOROOT/src/vendor), each made a module
# of its own, so that the tools below build offline: tools/spiderurl and tools/redirurl take their
# idna and httpguts from here — the copies net/http runs — and tools/unitables reads the idna, norm
# and bidi tables through one exporting file added to each (tools/unitables/lc_*.go.in). Outside
# build/ because the tools' go.mod files point at them by a fixed path. The stamp is named after the
# Go they were copied from, so that a different one makes them afresh.
GOROOT_X_STAMP = tools/.goroot-x/.from-$(shell $(GO127) env GOVERSION 2>/dev/null)
$(GOROOT_X_STAMP):
	rm -rf tools/.goroot-x && mkdir -p tools/.goroot-x && touch $@
GOROOT_X_TEXT = tools/.goroot-x/text/go.mod
$(GOROOT_X_TEXT): tools/unitables/lc_norm.go.in tools/unitables/lc_bidi.go.in $(GOROOT_X_STAMP)
	rm -rf tools/.goroot-x/text && mkdir -p tools/.goroot-x
	cp -r "$$($(GO127) env GOROOT)/src/vendor/golang.org/x/text" tools/.goroot-x/text
	cp tools/unitables/lc_norm.go.in tools/.goroot-x/text/unicode/norm/zz_lc.go
	cp tools/unitables/lc_bidi.go.in tools/.goroot-x/text/unicode/bidi/zz_lc.go
	printf 'module golang.org/x/text\n\ngo 1.21\n' > $@

GOROOT_X_NET = tools/.goroot-x/net/go.mod
$(GOROOT_X_NET): tools/unitables/lc_idna.go.in $(GOROOT_X_STAMP)
	rm -rf tools/.goroot-x/net && mkdir -p tools/.goroot-x
	cp -r "$$($(GO127) env GOROOT)/src/vendor/golang.org/x/net" tools/.goroot-x/net
	cp tools/unitables/lc_idna.go.in tools/.goroot-x/net/idna/zz_lc.go
	printf 'module golang.org/x/net\n\ngo 1.21\n' > $@

# The tables of idna.Lookup as net/http runs it — GOROOT's UTS #46 trie, NFC and bidi, Unicode
# 17.0.0 under Go 1.27 — for core/idna, core/unorm and core/ubidi, and the vectors test/unorm holds those to. See
# tools/unitables/main.go.
UNITABLES = tools/unitables/main.go tools/unitables/go.mod $(GOROOT_X_TEXT) $(GOROOT_X_NET)
$(BUILD)/gen/unitables_idna.h: $(UNITABLES)
	@mkdir -p $(dir $@)
	@tmp=$$(mktemp $(abspath $@).XXXXXX); trap 'rm -f "$$tmp"' EXIT HUP INT TERM; cd tools/unitables && $(GO127) run . tables idna > "$$tmp" && mv "$$tmp" $(abspath $@)
$(BUILD)/gen/unitables_nfc.h: $(UNITABLES)
	@mkdir -p $(dir $@)
	@tmp=$$(mktemp $(abspath $@).XXXXXX); trap 'rm -f "$$tmp"' EXIT HUP INT TERM; cd tools/unitables && $(GO127) run . tables nfc > "$$tmp" && mv "$$tmp" $(abspath $@)
$(BUILD)/gen/unitables_bidi.h: $(UNITABLES)
	@mkdir -p $(dir $@)
	@tmp=$$(mktemp $(abspath $@).XXXXXX); trap 'rm -f "$$tmp"' EXIT HUP INT TERM; cd tools/unitables && $(GO127) run . tables bidi > "$$tmp" && mv "$$tmp" $(abspath $@)
$(BUILD)/gen/univec.h: $(UNITABLES)
	@mkdir -p $(dir $@)
	@tmp=$$(mktemp $(abspath $@).XXXXXX); trap 'rm -f "$$tmp"' EXIT HUP INT TERM; cd tools/unitables && $(GO127) run . vectors > "$$tmp" && mv "$$tmp" $(abspath $@)
UNITABLES_H = $(BUILD)/gen/unitables_idna.h $(BUILD)/gen/unitables_nfc.h $(BUILD)/gen/unitables_bidi.h
$(BUILD)/src/core/idna.o: $(BUILD)/gen/unitables_idna.h
$(BUILD)/src/core/unorm.o: $(BUILD)/gen/unitables_nfc.h
$(BUILD)/src/core/ubidi.o: $(BUILD)/gen/unitables_bidi.h

$(BUILD)/test-unorm: test/unorm/test_unorm.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/core/gotext.h $(UNITABLES_H) $(BUILD)/gen/univec.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/unorm/test_unorm.c

# What the reference makes of "https://" + server name + a stored path — the :authority, :path, key
# and Authorization x/net writes, or no request at all — computed by Go's own net/http and net/url
# and x/net's own httpguts and idna. What lc_spider_target is held to. See tools/spiderurl/main.go.
$(BUILD)/gen/spiderurl_vectors.h: tools/spiderurl/main.go tools/spiderurl/go.mod $(GOROOT_X_TEXT) $(GOROOT_X_NET)
	@mkdir -p $(dir $@)
	cd tools/spiderurl && $(GO127) run . > $(abspath $@)

# The WINDOW_UPDATEs the reference sends while it reads a page, from Go's own io.ReadAll, bufio and
# gzip and x/net's inflow. What lc_spider_flow is held to. See tools/spiderflow/main.go.
$(BUILD)/gen/spiderflow_vectors.h: tools/spiderflow/main.go
	@mkdir -p $(dir $@)
	cd tools/spiderflow && $(GO127) run . > $(abspath $@)

# Which connection each request of a redirect chain goes out on — the one it has, a second opening,
# or none, the connection closed — from the reference's own http.Client over x/net's
# http2.Transport, handed the one connection whatever it dials. Needs vendor/x-net with
# internal/httpsfv. What get_client_conn (reality/fetch.c) is held to. See tools/spiderpool/main.go.
$(BUILD)/gen/spiderpool_vectors.h: tools/spiderpool/main.go tools/spiderpool/go.mod
	@mkdir -p $(dir $@)
	cd tools/spiderpool && $(GO127) run . > $(abspath $@)

# What http.Client and x/net make of a redirect's Location — the next URL, its referer, the
# connection it goes on, the :authority and :path, the Authorization and whether the cookie stays —
# from a real http.Client and x/net. What lc_url and lc_redirect are held to. See tools/redirurl.
$(BUILD)/gen/redirurl_vectors.h: tools/redirurl/main.go tools/redirurl/go.mod $(GOROOT_X_TEXT) $(GOROOT_X_NET)
	@mkdir -p $(dir $@)
	cd tools/redirurl && $(GO127) run . > $(abspath $@)

# src/core/rnd.c because the browser identity is now anchored per process and draws once at
# first use (lc_browser_chrome_anchored). The tests still exercise lc_browser_chrome directly with
# a draw of their own, which is what keeps them checkable against known values.
$(BUILD)/test-spider: test/spider/test_spider.c src/reality/spider.c src/reality/fetch.c src/core/gozip.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/paths.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c $(BUILD)/gen/hpack_static.h $(BUILD)/gen/spiderurl_vectors.h $(BUILD)/gen/redirurl_vectors.h $(UNITABLES_H)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/spider/test_spider.c src/reality/fetch.c src/core/gozip.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/paths.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c -lz

# The congestion control from patch 0009, checked as source rather than through the vtable: its
# functions are static, and a test that could only see ngtcp2_cc would be asserting that packets
# go in and a window comes out. QUIC_GEN first, because the file lives in the patched tree and
# that tree is what the stamp creates.
$(BUILD)/test-hybbr: test/hybbr/test_hybbr.c $(QUIC_GEN) $(NGTCP2_DIR)/lib/ngtcp2_hybbr.c $(BUILD)/gen/qgo_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -Wno-unused-function -o $@ test/hybbr/test_hybbr.c \
	    $(NGTCP2_DIR)/lib/ngtcp2_mem.c $(NGTCP2_DIR)/lib/ngtcp2_pcg.c

# The patches to ngtcp2 against what quic-go itself computes (tools/qgovec): the packet-number
# length, the long header, the first Initial of the parrot, the connection IDs, the receive
# windows, loss detection and the retransmission order, ECN, each on ngtcp2's own client with null
# crypto. ngtcp2_conn.c is included as source from the patched tree — -isystem keeps upstream's own
# warnings out of -Werror, as it keeps them out of every vendored object — so the library is linked
# without it. ngtcp2's test encoder lives in the upstream tree's tests/, not in the patched copy, and
# is built against the patched headers.
NGPATCH_OBJ = $(filter-out $(BUILD)/ngtcp2-obj/lib/ngtcp2_conn.o $(BUILD)/ngtcp2-obj/crypto/%.o,$(NGTCP2_OBJ))
$(BUILD)/ngtcp2-test/ngtcp2_test_helper.o: $(NGTCP2_UPSTREAM)/tests/ngtcp2_test_helper.c $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_CFLAGS) $(QUIC_INC) -c -o $@ $<
# The stream table, with conn.c included as source so that its static slot functions are in reach;
# everything else the QUIC stack links is linked as it is for lc-tunnel. See test/qslot.
$(BUILD)/test-qslot: test/qslot/test_qslot.c src/quic/conn.c $(filter-out $(BUILD)/src/quic/conn.o,$(QUIC_OBJ)) \
                     $(NGTCP2_OBJ) $(NGHTTP3_OBJ) $(LIB_OBJ) $(MLKEM_OBJ) $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ $(filter-out src/quic/conn.c,$(SOURCES)) $(LC_LIBS)

$(BUILD)/test-ngpatch: test/ngpatch/test_ngpatch.c $(NGPATCH_OBJ) $(BUILD)/ngtcp2-test/ngtcp2_test_helper.o \
                       $(BUILD)/gen/qgo_vectors.h $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -isystem $(NGTCP2_DIR)/lib $(QUIC_INC) -I$(NGTCP2_UPSTREAM)/tests -o $@ \
	    test/ngpatch/test_ngpatch.c $(NGPATCH_OBJ) $(BUILD)/ngtcp2-test/ngtcp2_test_helper.o

$(BUILD)/test-spiderpaths: test/spiderpaths/test_spiderpaths.c src/reality/paths.c src/reality/spider.c src/reality/fetch.c src/core/gozip.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c $(BUILD)/gen/hpack_static.h $(UNITABLES_H)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/spiderpaths/test_spiderpaths.c src/reality/paths.c src/reality/spider.c src/reality/fetch.c src/core/gozip.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c -lz -lm

# The spider's fetch against a scripted site: the redirects the reference followed on the stand
# tools/vendorcap/spiderredir, the windows it handed back, and what it never sent.
$(BUILD)/test-fetch: test/fetch/test_fetch.c src/reality/fetch.c src/core/gozip.c src/reality/spider.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/paths.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c $(BUILD)/gen/hpack_static.h $(BUILD)/gen/spiderflow_vectors.h $(BUILD)/gen/spiderpool_vectors.h $(UNITABLES_H)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/fetch/test_fetch.c src/reality/fetch.c src/core/gozip.c src/reality/spider.c src/reality/url.c src/core/goquote.c src/core/netip.c src/core/idna.c src/core/unorm.c src/core/ubidi.c src/reality/paths.c src/reality/browser.c src/core/rnd.c src/core/gomap.c src/h2/frame.c src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c src/quic/gorand.c -lz -lm

# What Xray's package init makes of a CPU, run from Xray's own browser.go: see tools/xraybrowser/gen.sh.
$(BUILD)/gen/xraybrowser_vectors.h: tools/xraybrowser/gen.sh tools/xraybrowser/main.go tools/xraybrowser/utils/aa_lc.go \
                                   vendor/Xray-core/common/utils/browser.go
	@mkdir -p $(dir $@)
	GO=$(GO127) sh tools/xraybrowser/gen.sh $@

$(BUILD)/test-browser: test/browser/test_browser.c src/reality/browser.c src/quic/gorand.c $(BUILD)/gen/xraybrowser_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/browser/test_browser.c src/quic/gorand.c

# The other half of test-hello, which the header calls the acceptance rule: the SHIPPED table
# built and compared byte for byte against uTLS's own message. -Itest/fphello for the frozen vector
# beside it; the test opens package/files/fingerprint.fpt itself, so it must run from the tree root,
# which is where every target here already runs.
# The TLS 1.2 suites uTLS would run against those this build has, over every hello that ships (T3).
$(BUILD)/test-tls12: test/tls12/test_tls12.c src/fp/hello.c src/fp/fpt.c src/core/rnd.c src/core/buf.c \
                     src/tls/suite.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/tls12/test_tls12.c src/fp/hello.c src/fp/fpt.c src/core/rnd.c \
	    src/core/buf.c src/tls/suite.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c $(LC_LIBS)

# Go's x509.ParseCertificate, verdict and words, against what go1.26.6 answered for every certificate
# tools/x509read wrote down — see cert/x509go.h.
X509GO_SRC = src/cert/x509go.c src/reality/url.c src/core/goquote.c src/core/netip.c
$(BUILD)/test-x509go: test/x509go/test_x509go.c test/x509go/reference.h $(X509GO_SRC) src/cert/mldsa.c $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ test/x509go/test_x509go.c $(X509GO_SRC) src/cert/mldsa.c $(CHAIN_KECCAK) $(LC_LIBS)

$(BUILD)/test-fphello: test/fphello/test_fphello.c test/fphello/reference_firefox.h \
                       src/fp/hello.c src/fp/fpt.c src/core/rnd.c src/core/buf.c src/tls/suite.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Itest/fphello -o $@ test/fphello/test_fphello.c src/fp/hello.c \
	    src/fp/fpt.c src/core/rnd.c src/core/buf.c src/tls/suite.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c $(LC_LIBS)

# The padding draws, whose distribution is part of the wire fingerprint: the pool that replaced one
# getrandom syscall per byte had to leave the produced characters bit-for-bit as they were. Includes
# pad.c for its statics, so pad.c is a prerequisite and not a source.
$(BUILD)/test-pad: test/pad/test_pad.c src/quic/pad.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/pad/test_pad.c src/core/rnd.c

# src/core/rnd.c is deliberately NOT linked here. The suite supplies lc_rnd itself, because the two
# properties worth pinning — that a draw below the rejection threshold is drawn again, and that a
# source which fails is not read as zero — are invisible against a real source.
$(BUILD)/test-hop: test/hop/test_hop.c src/quic/hop.c src/quic/hop.h src/core/portunion.c src/core/portunion.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/hop/test_hop.c

# Who owns a stream's send buffer while ngtcp2 is holding it. Split out of conn.c because conn.c
# cannot be loaded without the vendored QUIC stack, so the rule sat in it unasked, and the version
# that got it wrong passed every check in this file.
$(BUILD)/test-qtx: test/qtx/test_qtx.c src/quic/txbuf.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/qtx/test_qtx.c

# How large a proxied UDP payload may be. Split out of conn.c for the same reason as txbuf.c above,
# and with more cause: this arithmetic was wrong by fifty-seven bytes on the frame wrapper for
# months while a comment beside it said the fault had been fixed. Nothing could contradict the
# comment, because conn.c cannot be loaded without the vendored QUIC stack and so nothing ran.
$(BUILD)/test-qdgram: test/qdgram/test_qdgram.c src/quic/dgram.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/qdgram/test_qdgram.c src/quic/dgram.c

# Putting a proxied UDP packet back together. Split out of conn.c for the reason dgram.c above was,
# and with the worst input of the three: fragments arrive from the node in any order, any number of
# times, and the parser that vetted them is a different file.
$(BUILD)/test-reasm: test/reasm/test_reasm.c src/quic/reasm.c src/quic/hy.c src/quic/varint.c \
                     src/quic/pad.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/reasm/test_reasm.c src/quic/reasm.c src/quic/hy.c \
	    src/quic/varint.c src/quic/pad.c src/core/rnd.c $(LC_LIBS)

# Which UDP session a datagram belongs to. Split out of conn.c when the thirty-two sessions it held
# became no ceiling at all: a sorted array standing in for the reference's map has to earn what the
# map gives for free — each id once, and a lookup that finds the right one whatever was closed
# around it.
$(BUILD)/test-udptab: test/udptab/test_udptab.c src/quic/udptab.c src/quic/udptab.h src/quic/reasm.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/udptab/test_udptab.c src/quic/udptab.c

# ngtcp2's headers come along for the receive buffer's test (test-qrx, below) for a constant — the ceiling this buffer may grow to is the window quic/params.h advertises, and
# the two being the same number is the point — but nothing of ngtcp2 is linked.
# The padding draws and the salt length come from the two modules Gecko sits between, so both come
# along; nothing of ngtcp2 does, because a frame is bytes and knows nothing about QUIC beyond one bit
# of the first one.
$(BUILD)/test-gecko: test/gecko/test_gecko.c src/quic/gecko.c src/quic/pad.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/gecko/test_gecko.c src/quic/pad.c src/core/rnd.c

$(BUILD)/test-qrx: test/qrx/test_qrx.c src/quic/rxbuf.c $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ test/qrx/test_qrx.c

# Links ngtcp2's library objects for one function — ngtcp2_transport_params_default — because what
# this checks is the whole block as it leaves this client, defaults included. Asserting only the
# fields we assign would say nothing about the ones we do not, and those go on the wire too.
#
# The library only, without crypto/shared.o: that file is the half of ngtcp2 that calls into a
# backend, and the backend is src/quic/qcrypto.c, which would drag mbedTLS and the rest of the client
# into a test about eleven numbers.
QPARAMS_OBJ = $(filter-out $(BUILD)/ngtcp2-obj/crypto/%.o,$(NGTCP2_OBJ))
# src/quic/varint.c is named because params.c reads the peer's transport parameters with
# lc_varint_get — the QUIC varint reader that already existed, rather than a second copy of it in
# this file. test_qparams.c #includes params.c, so the reader has to come from somewhere, and it
# comes from the one that ships.
$(BUILD)/test-qparams: test/qparams/test_qparams.c src/quic/params.c src/quic/varint.c \
                       $(QPARAMS_OBJ) $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ test/qparams/test_qparams.c src/quic/varint.c \
	    $(QPARAMS_OBJ)

# Header protection, against RFC 9001's own vectors. Needs $(QUIC_INC) because qcrypto.c is written
# against ngtcp2's crypto headers, and mbedcrypto because that is what it calls; it needs no part of
# ngtcp2's library, since every function this exercises is defined in qcrypto.c itself.
$(BUILD)/test-qhp: test/qhp/test_qhp.c src/quic/qcrypto.c src/tls/aead.c src/tls/hkdf.c \
                   src/tls/suite.c src/core/rnd.c $(GHASH_SRC) $(CHACHA_SRC) $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ test/qhp/test_qhp.c src/tls/aead.c src/tls/hkdf.c \
	    src/tls/suite.c src/core/rnd.c $(GHASH_SRC) $(CHACHA_SRC) $(LC_LIBS)

# What qtls.c calls since it learned to parrot Chrome, for the two suites that #include it: the hello
# is built from a table by fp/hello.c, a compressed certificate is opened by tls/certcomp.c (with
# the decoders). The header is the table.
QTLS_CHROME_SRC = src/fp/hello.c src/fp/fpt.c src/tls/certcomp.c src/quic/chrome_hello.h \
                  src/cert/x509go.c src/reality/url.c src/core/goquote.c src/core/netip.c

# The certificate pin, which is the whole of the QUIC plane's answer to who the node is. Internal to
# qtls.c for the same reason the reassembler is internal to client.c, and included the same way.
# hybrid.c and mlkem.c joined this list when the QUIC ClientHello started offering X25519MLKEM768,
# which is the group the reference offers first: qtls.c is #included by the test, so its new callees
# have to be linked here or the suite stops building. $(MLKEM_SRC) is named as a prerequisite as
# well as on the command line, for the reason the test-mlkem rule gives.
$(BUILD)/test-qpin: test/qpin/test_qpin.c test/qpin/reference_misplaced.h src/quic/qtls.c \
                    src/tls/stdmsg.c src/tls/msg.c src/tls/hkdf.c \
                    src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
                    src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/cert/cert.c $(filter-out $(QTLS_CHROME_SRC),$(CHAIN_SRC)) \
                    src/tls/hybrid.c src/tls/mlkem.c src/tls/mlkem1024.c $(MLKEM_SRC) \
                    src/core/buf.c src/core/rnd.c $(BUILD)/gen/test_vectors.h \
                    $(QTLS_CHROME_SRC) $(BROTLI_OBJ) $(ZSTD_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -o $@ test/qpin/test_qpin.c src/tls/stdmsg.c src/tls/msg.c src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
	    src/tls/hkdf.c src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/cert/cert.c $(filter-out $(QTLS_CHROME_SRC),$(CHAIN_SRC)) \
	    src/tls/hybrid.c src/tls/mlkem.c src/tls/mlkem1024.c $(MLKEM_SRC) src/core/buf.c \
	    $(filter %.c,$(QTLS_CHROME_SRC)) $(BROTLI_OBJ) $(ZSTD_OBJ) \
	    src/core/rnd.c $(LC_LIBS)

# The QUIC hello, against what the reference client sends — see test/qhello/test_qhello.c
# for where the expected values were measured and why the cipher ORDER is not among them.
# Same sources as test-qpin because it includes the same translation unit whole: qtls.c is
# where the hello is built, and build_hello is static.
$(BUILD)/test-qhello: test/qhello/test_qhello.c $(BUILD)/gen/trust_anchors.h src/quic/qtls.c src/tls/stdmsg.c src/tls/msg.c src/tls/hkdf.c \
                      src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
                      src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/cert/cert.c $(filter-out $(QTLS_CHROME_SRC),$(CHAIN_SRC)) \
                      src/tls/hybrid.c src/tls/mlkem.c src/tls/mlkem1024.c $(MLKEM_SRC) \
                      src/core/buf.c src/core/rnd.c $(BUILD)/gen/test_vectors.h \
                      $(QTLS_CHROME_SRC) $(BROTLI_OBJ) $(ZSTD_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -o $@ test/qhello/test_qhello.c src/tls/stdmsg.c src/tls/msg.c \
	    src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
	    src/tls/hkdf.c src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/cert/cert.c $(filter-out $(QTLS_CHROME_SRC),$(CHAIN_SRC)) \
	    src/tls/hybrid.c src/tls/mlkem.c src/tls/mlkem1024.c $(MLKEM_SRC) src/core/buf.c \
	    $(filter %.c,$(QTLS_CHROME_SRC)) $(BROTLI_OBJ) $(ZSTD_OBJ) \
	    src/core/rnd.c $(LC_LIBS)

# What the three suites cost on the machine this is built for. Not part of `check` — it measures
# hardware rather than asserting anything, and on a build host it would measure the wrong hardware.
# Cross-compile it and run it on the device: it answers "what is this box's ceiling" in five seconds,
# which is the first number worth having before any argument about throughput.
#
# One thing TEST_CFLAGS does not carry and this target needs, because unlike every other test it is
# meant to be cross-compiled and run on the device: the vendored mbedTLS headers, which only the
# programs' CFLAGS pick up. (_GNU_SOURCE was the other, and is in TEST_CFLAGS now.)
#
#   make BUILD=build-mips CC=mipsel-openwrt-linux-gcc \
#        MBEDTLS_INC=vendor/mbedtls/include MBEDTLS_LIB=dl/mipslib build-mips/bench-aead
#
# -fPIE, EXPLICITLY, and this rule is the only one that needs it: TEST_CFLAGS has no -fPIE (a test
# that runs on the build host does not need one) while LDFLAGS has -pie, which every SHIPPED binary
# gets from the programs' own CFLAGS. Nowhere else do the two meet. On x86-64 the mismatch links
# anyway; on mipsel the linker refuses every relocation in the file — "cannot be used when making a
# shared object; recompile with -fPIC" — so the command written directly above this line did not
# work at all, on the one target it exists for. Found by running it.
#
# AND AT THE FLAGS THE BINARY SHIPS WITH, which this rule did not do: it built everything at
# TEST_CFLAGS, and TEST_CFLAGS says -O1. For a test that ASSERTS something the level is irrelevant
# and -O1 is the right trade. This one asserts nothing — its entire output is a speed — and a speed
# measured at an optimization level nobody ships is the speed of a program that does not exist.
# Measured on the AX3000T (Cortex-A53), 19 September, same box, same run:
#
#   AES-128-GCM          99 Mbit/s at -O1     175 Mbit/s at the flags below
#   ChaCha20-Poly1305   301 Mbit/s           301 Mbit/s
#
# The second line is what makes this a fact rather than a suspicion. ChaCha20-Poly1305 is the
# DEVICE's mbedTLS doing the work — compiled long ago, somewhere else, untouched by anything here —
# so it reads the same either way. AES-GCM is ours: aead.c runs the counter and BearSSL's
# ghash_ctmul authenticates, both compiled by this rule, and only that number moved. The bench was
# not reporting the box's ceiling; it was reporting its own build. 99 was quoted as the ceiling.
#
# So each source is now built the way the shipped binary builds it, and the three differ: src/ at
# $(CFLAGS), which is -Os plus the hardening; the GHASH, ChaCha20 and Poly1305 at $(GHASH_CFLAGS),
# which is -O2 and the reason they cannot simply share one line; and only the harness itself at
# TEST_CFLAGS.
$(BUILD)/bench-aead: test/bench/bench_aead.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) \
	    -c -o $(BUILD)/bench-aead-aead.o src/tls/aead.c
	$(CC) $(GHASH_CFLAGS) -c -o $(BUILD)/bench-aead-ghash.o $(GHASH_SRC)
	$(CC) $(GHASH_CFLAGS) -c -o $(BUILD)/bench-aead-chacha.o src/tls/chacha.c
	$(CC) $(GHASH_CFLAGS) -c -o $(BUILD)/bench-aead-poly1305.o src/tls/poly1305.c
	$(CC) $(TEST_CFLAGS) -fPIE $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) $(EXTRA_CFLAGS) \
	    -c -o $(BUILD)/bench-aead-main.o test/bench/bench_aead.c
	$(CC) -o $@ $(BUILD)/bench-aead-main.o $(BUILD)/bench-aead-aead.o \
	    $(BUILD)/bench-aead-ghash.o $(BUILD)/bench-aead-chacha.o $(BUILD)/bench-aead-poly1305.o \
	    $(LDFLAGS) $(LC_LIBS)

# The asymmetric half of the same question — see test/bench/bench_kex.c for why it was asked.
# Built and run the same way, on the device:
#
#   make BUILD=build-mips CC=mipsel-openwrt-linux-gcc \
#        MBEDTLS_INC=vendor/mbedtls/include MBEDTLS_LIB=dl/mipslib build-mips/bench-kex
#
# MLKEM_OBJ and MLKEM_INC are what this one needs beyond bench-aead's recipe: mlkem-native is
# compiled from source with its own flags (see the vendored block above), so the objects are
# prerequisites and its headers have to be on the include path for mlkem.c to find <mlkem_native.h>.
#
# The two -D are NOT optional and not decoration. mlkem-native names every exported symbol after
# MLK_CONFIG_NAMESPACE_PREFIX, so a translation unit that includes its header without them declares
# nothing our wrapper calls: `implicit declaration of function 'mlkem768_keypair'`, which -Werror
# turns into a failed build. The ordinary object rule passes both to EVERY file for exactly this
# reason; this target has its own recipe and therefore its own copy.
#
# AND AT THE SHIPPED FLAGS, for the reason spelled out at bench-aead: this is the other half of the
# same pair, its numbers are quoted beside that one's, and leaving one of two identical rules at an
# optimization level nobody ships makes the pair disagree for a reason nobody can see. Everything
# here except the harness is src/, so everything here except the harness is built at $(CFLAGS).
#
# ⚠️ AND IT CHANGED NOTHING, which is worth writing down because the fix next door changed 99 into
# 175. Measured on the AX3000T, both binaries, same box, same minute: ML-KEM keygen 0.29 against
# 0.30 ms, X25519 4.14 against 4.14, the hybrid pair 4.39/4.65 against 4.41/4.66, Ed25519 verify
# 23.88 against 24.26 — the -Os build very slightly SLOWER, which is what -Os is for. The reason is
# where the work is: the big numbers are mbedTLS's bignum, which is the device's library and was
# never compiled by this rule, and ML-KEM, which comes in as $(MLKEM_OBJ) from its own rule at
# $(MLKEM_CFLAGS) and was already right. What this rule compiles is thin glue over both. So the
# change is for consistency, and anyone expecting these numbers to move should not.
$(BUILD)/bench-kex: test/bench/bench_kex.c src/tls/hybrid.c src/tls/mlkem.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c \
                    src/tls/ed25519.c src/core/rnd.c $(MLKEM_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) \
	    -c -o $(BUILD)/bench-kex-hybrid.o src/tls/hybrid.c
	$(CC) $(CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) \
	    -c -o $(BUILD)/bench-kex-mlkem.o src/tls/mlkem.c
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -c -o $(BUILD)/bench-kex-kex.o src/tls/kex.c
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -c -o $(BUILD)/bench-kex-x25519.o src/tls/x25519.c
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -c -o $(BUILD)/bench-kex-ed25519.o \
	    src/tls/ed25519.c
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -c -o $(BUILD)/bench-kex-fe.o src/tls/fe25519.c
	$(CC) $(CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -c -o $(BUILD)/bench-kex-rnd.o src/core/rnd.c
	$(CC) $(TEST_CFLAGS) -fPIE $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) \
	    -c -o $(BUILD)/bench-kex-main.o test/bench/bench_kex.c
	$(CC) -o $@ $(BUILD)/bench-kex-main.o $(BUILD)/bench-kex-hybrid.o $(BUILD)/bench-kex-mlkem.o \
	    $(BUILD)/bench-kex-kex.o $(BUILD)/bench-kex-x25519.o $(BUILD)/bench-kex-fe.o $(BUILD)/bench-kex-ed25519.o $(BUILD)/bench-kex-rnd.o \
	    $(MLKEM_OBJ) $(LDFLAGS) $(LC_LIBS)

# Message framing across record boundaries. The reassembler is internal to client.c, so the test
# includes that translation unit whole rather than driving the state machine from outside — which
# would need a live server and would prove less about the framing. client.c is therefore a
# prerequisite but NOT a source on the command line; it arrives through the #include.
$(BUILD)/test-hsframe: test/hsframe/test_hsframe.c src/tls/client.c src/tls/msg.c src/tls/hkdf.c src/tls/prf12.c \
                       src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
                       src/tls/aead.c src/tls/record.c src/tls/transcript.c src/tls/kex.c src/tls/x25519.c \
                       src/tls/suite.c src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c src/cert/cert.c $(CHAIN_SRC) src/tls/certcomp.c \
                       src/fp/hello.c src/fp/fpt.c src/core/buf.c src/core/rnd.c src/net/sock.c \
                       src/net/loop.c src/reality/reality.c $(MLKEM_SRC) $(GHASH_SRC) $(CHACHA_SRC) \
                       $(BROTLI_OBJ) $(ZSTD_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -o $@ \
	    test/hsframe/test_hsframe.c src/tls/msg.c src/tls/hkdf.c src/tls/prf12.c src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
	    src/tls/aead.c src/tls/record.c \
	    src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c \
	    src/cert/cert.c $(CHAIN_SRC) src/tls/certcomp.c src/fp/hello.c src/fp/fpt.c src/core/buf.c src/core/rnd.c src/net/sock.c \
	    src/net/loop.c src/reality/reality.c $(MLKEM_SRC) $(GHASH_SRC) $(CHACHA_SRC) $(BROTLI_OBJ) $(ZSTD_OBJ) $(LC_LIBS)

# The seam between the handshake machine and the program that drives it, tested from OUTSIDE both.
#
# Links nothing of ours: it runs `build/lc-tunnel` as a child against a stand-in node and reads what
# comes back off a socket. That is the point — a suite that called into src/tls would have passed on
# the tree where lc-tunnel never asked the handshake for its alert, because that tree's library was
# correct and only the wiring was missing. lc-tunnel is an order-only prerequisite: the binary must
# exist, but this test does not need relinking when it changes (`check` builds `all` first anyway).
$(BUILD)/test-seam: test/seam/test_seam.c | $(BUILD)/lc-tunnel
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -DLC_TEST_TUNNEL='"$(BUILD)/lc-tunnel"' -o $@ test/seam/test_seam.c

# The alerts a refusal owes the peer. Same shape as test-hsframe and for the same reason: what it
# asks about — whether an alert was recorded, and which — is internal to client.c, and no public
# call answers it. client.c arrives through the #include, not on the command line.
$(BUILD)/test-alert: test/alert/test_alert.c src/tls/client.c src/tls/msg.c src/tls/hkdf.c src/tls/prf12.c \
                     src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
                     src/tls/aead.c src/tls/record.c src/tls/transcript.c src/tls/kex.c src/tls/x25519.c \
                     src/tls/suite.c src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c src/cert/cert.c $(CHAIN_SRC) src/tls/certcomp.c \
                     src/fp/hello.c src/fp/fpt.c src/core/buf.c src/core/rnd.c src/net/sock.c \
                     src/net/loop.c src/reality/reality.c $(MLKEM_SRC) $(GHASH_SRC) $(CHACHA_SRC) \
                     $(BROTLI_OBJ) $(ZSTD_OBJ) $(BUILD)/gen/certverify_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(MLKEM_INC) -DMLK_CONFIG_PARAMETER_SET=768 \
	    -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem768 -o $@ \
	    test/alert/test_alert.c src/tls/msg.c src/tls/hkdf.c src/tls/prf12.c src/tls/certverify.c src/tls/ed25519.c src/tls/fe25519.c \
	    src/tls/aead.c src/tls/record.c \
	    src/tls/transcript.c src/tls/kex.c src/tls/x25519.c src/tls/suite.c src/tls/mlkem.c src/tls/mlkem1024.c src/tls/hybrid.c \
	    src/cert/cert.c $(CHAIN_SRC) src/tls/certcomp.c src/fp/hello.c src/fp/fpt.c src/core/buf.c src/core/rnd.c src/net/sock.c \
	    src/net/loop.c src/reality/reality.c $(MLKEM_SRC) $(GHASH_SRC) $(CHACHA_SRC) $(BROTLI_OBJ) $(ZSTD_OBJ) $(LC_LIBS)

# Every suite there is, named once, in the order they are run.
#
# This list existed three times — as `check`'s prerequisites, as twenty lines of recipe, and as TESTS
# for the header dependency below — and the three had already drifted: a test missing from one of
# them either never runs, or runs without being rebuilt when the header it is written against
# changes. Both failures are silent and both look like a green suite. Adding a test is now one word
# on one line, which is the only version of this that stays true.
# Ed25519, the one asymmetric primitive this client implements itself, against RFC 8032 §7.1.
# The .c is included by the test rather than linked, so that the negative cases can reach L_DEC and
# build a signature with S out of range — which is a refusal no public API can be asked for.
$(BUILD)/test-ed25519: test/ed25519/test_ed25519.c src/tls/ed25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/ed25519/test_ed25519.c src/tls/fe25519.c $(LC_LIBS)

$(BUILD)/test-spider-retention: test/spiderpaths/test_retention.c src/reality/paths.c src/core/rnd.c src/core/gomap.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ test/spiderpaths/test_retention.c src/core/rnd.c src/core/gomap.c

# Retain the actual supervisor while discarding the unused tunnel entry point.
$(BUILD)/test-supervisor: test/supervisor/test_supervisor.c src/cmd/lc-tunnel/main.c src/net/sock.c src/core/rnd.c $(HEADERS) $(BUILD)/gen/version.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -DLC_HYSTERIA=0 -fPIE -ffunction-sections -fdata-sections -pthread -o $@ test/supervisor/test_supervisor.c src/net/sock.c src/core/rnd.c -Wl,--gc-sections $(LDFLAGS)

$(BUILD)/test-listener: test/loop/test_listener.c src/cmd/lc-tunnel/main.c src/net/loop.c src/net/sock.c src/core/say.c $(HEADERS) $(BUILD)/gen/version.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(if $(MBEDTLS_INC),-I$(MBEDTLS_INC)) -DLC_HYSTERIA=0 -fPIE -ffunction-sections -fdata-sections -pthread -o $@ test/loop/test_listener.c src/net/loop.c src/net/sock.c src/core/say.c -Wl,--gc-sections $(LDFLAGS)

$(BUILD)/gen/spiderchoice_vectors.h: tools/spiderchoice/main.go tools/spiderchoice/prepare.go tools/spiderchoice/gen.sh tools/spiderchoice/go.mod docker/Dockerfile
	GO127=$(GO127) sh tools/spiderchoice/gen.sh $@

$(BUILD)/test-spider-choice: test/spiderpaths/test_choice.c src/reality/paths.c src/core/rnd.c src/core/gomap.c $(BUILD)/gen/spiderchoice_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ test/spiderpaths/test_choice.c src/core/rnd.c src/core/gomap.c -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free

$(BUILD)/bench-spider-choice: test/bench/bench_spider_choice.c src/reality/paths.c src/core/rnd.c src/core/gomap.c
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ test/bench/bench_spider_choice.c src/core/rnd.c src/core/gomap.c $(LDFLAGS)

TEST_NAMES = args say hkdf aead record handshake hsframe alert seam pad qpin qhello mlkem msg cert reality hello blake2b ed25519 kex \
             h3 hy vless vision hpack h2frame xhttp events share qtx qrx qparams gecko qhp fphello browser spider spiderpaths hybbr ngpatch xudp \
             chain certcomp qdgram obfs reasm udptab vfilter vresp certverify prefix keys fpt hop x25519 reader sendq \
             x25519-ref10 ed25519-ref10 aead-mbedpoly gomap post fetch fetch-cleanup headerbudget spider-tunnel hy-tunnel gozip gozip-parallel unorm qslot tls12 x509go rxopen recopen rawin goresolve mldsa gosig ed25519go sendq-poll spider-retention spider-choice supervisor listener vision-io vision-close
TESTS = $(TEST_NAMES:%=$(BUILD)/test-%)


# Go's x509 checkSignature (go1.27.1), verdict and words, against what Go answered for every vector
# tools/sigvec wrote down — see cert/gosig.h. The test stands in for ML-DSA (lc_mldsa_verify) with
# Go's recorded answers, and checks it is asked exactly when Go asks.
$(BUILD)/test-gosig: test/gosig/test_gosig.c test/gosig/reference.h src/cert/gosig.c src/cert/gosig.h src/cert/mldsa.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/gosig/test_gosig.c src/cert/gosig.c $(LC_LIBS)

# The same Ed25519 vectors put to tls/ed25519.c, which uTLS's CertificateVerify reaches through the
# same ed25519.Verify on both planes (its decoding is go1.26.6's and go1.27.1's alike): every verdict
# must be Go's.
$(BUILD)/test-ed25519go: test/gosig/test_gosig.c test/gosig/reference.h src/cert/gosig.c src/cert/gosig.h \
                         src/tls/ed25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -DLC_GOSIG_VS_TLS_ED25519 -o $@ test/gosig/test_gosig.c src/cert/gosig.c \
	    src/tls/ed25519.c src/tls/fe25519.c $(LC_LIBS)
# Go 1.27.1's mldsa.NewPublicKey and mldsa.Verify(pub, msg, sig, nil), verdict and words, against what
# it answered for every key, message and signature tools/mldsavec wrote down — see cert/mldsa.h.
$(BUILD)/test-mldsa: test/mldsa/test_mldsa.c test/mldsa/reference.h src/cert/mldsa.c src/cert/mldsa.h \
                     $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -o $@ test/mldsa/test_mldsa.c src/cert/mldsa.c $(CHAIN_KECCAK)

# cert/goverify.c against go1.27.1's own Certificate.Verify and policiesValid, call for call: the
# program reads the record test/goverify/run.sh makes of crypto/x509's tests (check-goverify).
$(BUILD)/test-goverify: test/goverify/test_goverify.c $(CHAIN_SRC) $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -pthread -o $@ test/goverify/test_goverify.c \
	    $(filter-out src/cert/chain.c src/cert/goverify.c,$(CHAIN_SRC)) $(CHAIN_KECCAK) $(LC_LIBS)

check-goverify: $(BUILD)/test-goverify
	@sh test/goverify/run.sh $(BUILD)

# The system store, as go1.27.1's loadSystemRoots builds it and as cert/goverify.c does, scenario
# for scenario (test/goroots/run.sh against tools/x509roots).
$(BUILD)/goroots: test/goroots/roots.c $(CHAIN_SRC) $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -pthread -o $@ test/goroots/roots.c \
	    $(filter-out src/cert/chain.c,$(CHAIN_SRC)) $(CHAIN_KECCAK) $(LC_LIBS)

check-goroots: $(BUILD)/goroots
	@sh test/goroots/run.sh $(BUILD)

# `all` first, so that every tool compiles before a single assertion is made. Without it `check` was
# green on a tree where a tool did not build at all: the suites link the modules they exercise
# directly and never touch src/cmd, so the eight programs — the only artefacts anybody installs —
# were outside everything this target checks.
# ⚠️ AND EVERY SUITE HAS TO ASSERT SOMETHING, which this loop did not require until 2026-09-02.
#
# It ran each binary and looked at the exit code, and a suite that asserts nothing exits zero. So a
# main() whose calls were commented out during a debugging session, a case list that stopped being
# reached, a file emptied by a bad merge — all of them pass, and pass while printing their own
# cheerful closing line, because that line is printed on `fails == 0` and zero checks is zero
# failures. This is the same silent-green shape the tree already guards against elsewhere: a broken
# build gives no FAIL either, and `check-builds` exists because of it.
#
# Held per suite rather than as a total. A total is a number somebody has to update on purpose, and
# every number in this file that had to be maintained by hand has at some point been wrong; "this
# binary printed at least one result" needs no maintenance and catches the case that matters.
# ⚠️ AND A SUITE THAT NEVER RETURNS IS A FAILURE, not a gate that waits forever.
#
# Everything above guards against a suite that says nothing. A suite that says nothing BECAUSE IT IS
# STILL RUNNING got past all of it: `out=$$($$t)` waits, and the whole gate waits with it — no
# output, no verdict, no timeout, on a target that CI runs unattended.
#
# Not hypothetical. Mutating lc_hop_port to drop lc_rnd's error — which is exactly the shape both
# copies of that code had before it was one — spins the rejection loop forever, because a source
# that fails writes nothing and the value it did not write stays below the threshold. That mutation
# is supposed to be caught by test/hop, and it is; but without a bound here it would have been
# "caught" by a gate that hangs, which no one reads as a failing test.
#
# Two minutes is far past every suite in this tree (the slowest is a few seconds) and far short of
# any patience CI has. 124 is what timeout(1) exits with when it fires, and it is reported as its
# own failure rather than folded into "asserted nothing": a suite killed mid-run may well have
# printed some ok lines before it stopped, and calling that "asserted nothing" would name the wrong
# fault.
TEST_TIMEOUT = 120

check: all $(TESTS)
	@for t in $(TESTS); do \
	    out=$$(timeout $(TEST_TIMEOUT) $$t); rc=$$?; \
	    printf '%s\n' "$$out"; \
	    [ $$rc -ne 124 ] || { echo "  FAIL  $$t did not finish within $(TEST_TIMEOUT)s"; exit 1; }; \
	    [ $$rc -eq 0 ] || exit 1; \
	    n=$$(printf '%s\n' "$$out" | grep -c '^  ok '); \
	    [ "$$n" -gt 0 ] || { echo "  FAIL  $$t asserted nothing at all"; exit 1; }; \
	    echo; \
	done
	@$(MAKE) --no-print-directory check-builds
	@$(MAKE) --no-print-directory check-device
	@$(MAKE) --no-print-directory check-arm64
	@$(MAKE) --no-print-directory check-x86

# Exercise CPU dispatch on hardware profiles, without a test-only algorithm override.
# Every instruction required by Go's x86 GCM condition is removed independently;
# the same AEAD answers must hold on each profile and the selected path is asserted.
check-x86: $(BUILD)/test-aead
	@case "$$($(CC) -dumpmachine)" in x86_64*) ;; \
	    *) echo "check-x86: x86 instructions are not compiled for this host target"; exit 0;; esac; \
	for cpu in max max,aes=off max,pclmulqdq=off max,ssse3=off max,sse4.1=off; do \
	    expected=generic; [ "$$cpu" != max ] || expected=pclmul; \
	    out=$$(timeout $(TEST_TIMEOUT) qemu-x86_64 -cpu "$$cpu" $(BUILD)/test-aead 2>&1) || { \
	        printf '%s\n' "$$out"; echo "  FAIL  x86 AEAD profile $$cpu"; exit 1; }; \
	    printf '%s\n' "$$out" | grep -q "^GHASH: $$expected$$" || { \
	        echo "  FAIL  x86 profile $$cpu did not select $$expected"; exit 1; }; \
	    n=$$(printf '%s\n' "$$out" | grep -c '^  ok '); \
	    [ "$$n" -gt 0 ] || { echo "  FAIL  x86 AEAD profile asserted nothing"; exit 1; }; \
	    echo "  ok    x86 AES-GCM agrees with mbedTLS: $$cpu selects $$expected, $$n checks"; \
	done

.PHONY: check-x86

# ⚠️ THE BUILD THAT ACTUALLY REACHES A ROUTER, WHICH NOTHING HERE COMPILED UNTIL NOW.
#
# Everything above this line is x86-64. The device is mipsel — 32-bit, different long, different
# alignment, a different libc — and the warnings this tree treats as errors are exactly the ones that
# differ between the two: -Wconversion on a size_t that is half the width, a %zu that is no longer a
# %lu, a struct whose members land elsewhere. So "830 ok" could be, and was, entirely compatible with
# a tree that does not build for the only hardware this program exists for. Found the ordinary way:
# by cross-compiling by hand four times in one afternoon because the suite would not do it.
#
# ⚠️ AND IT FAILS RATHER THAN SKIPS WHEN THE TOOLCHAIN IS NOT THERE, which is the whole point and the
# reason this is not two lines. A check that quietly does not run is worse than no check: it turns
# "the device build was not tried" into a green suite, which is the precise fault being closed here.
# The tree already requires provisioning before `make check` means anything — vendor/ is fetched, not
# tracked (vendor/.gitignore ignores everything in it) — so the toolchain is one more line on a list
# that already exists, and docs/BUILD.md's "Cross-compiling for the router" is where both live.
#
# MIPSEL AND AARCH64 — the two the boxes in this document run on: MT7621 is mipsel, the AX3000T is
# mediatek/filogic, aarch64. OpenWrt also runs on x86_64, armv7, armv6 and mips; those are
# still not built here, and that is a gap named rather than covered. The aarch64 pass links against
# dl/a64lib, stubs made by the procedure in docs/BUILD.md ("The same for aarch64") and refused rather than
# skipped when absent, exactly as dl/mipslib is. It was only check-arm64 until 2026-09-24 — test-aead,
# statically against mbedTLS from vendor/ — so the programs a household on an AX3000T actually runs
# were compiled for it by hand or not at all.
#
# COST: eleven seconds when the object tree is warm, seven minutes from nothing — and the seven
# minutes are mbedTLS, BearSSL and mlkem-native, which change on the day they are re-vendored and
# never otherwise. Both configurations, both `all`, for the reason check-builds already gives: each
# is what ships to somebody, and the eight programs are the only artefacts anybody installs.
# ⚠️ NAMED BY THE COMPILER IT MUST CONTAIN, NOT BY BEING FIRST IN THE DIRECTORY.
#
# This was `$(firstword $(wildcard dl/tc/*/toolchain-*))` and worked for as long as dl/tc held
# exactly one toolchain. A second one — mediatek/filogic, unpacked so the aarch64 build could be
# made real — broke it immediately and in the confusing direction: "mediatek" sorts before "ramips",
# so the gate picked the aarch64 tree, looked for mipsel-openwrt-linux-gcc inside it, did not find
# it, and reported "no cross toolchain under dl/tc — the ROUTER build was not checked at all". The
# toolchain was there; the wrong one was chosen.
#
# Matching on the directory name would work today and rot the same way, so the wildcard asks for the
# binary this build actually invokes.
CROSS_CC = mipsel-openwrt-linux-gcc
CROSS_TC = $(patsubst %/bin/$(CROSS_CC),%,$(firstword $(wildcard dl/tc/*/toolchain-*/bin/$(CROSS_CC))))

check-device:
	@tc="$(CROSS_TC)"; \
	if [ -z "$$tc" ] || [ ! -x "$$tc/bin/$(CROSS_CC)" ]; then \
	    echo "  FAIL  no cross toolchain under dl/tc — the ROUTER build was not checked at all"; \
	    echo "        This suite refuses to pass on that: everything else it runs is x86-64, and"; \
	    echo "        the device is 32-bit mipsel. See docs/BUILD.md, 'Cross-compiling for the router'."; \
	    exit 1; \
	fi; \
	if [ ! -f dl/mipslib/libmbedcrypto.so ]; then \
	    echo "  FAIL  dl/mipslib has no link stubs — the ROUTER build cannot be linked"; \
	    echo "        The device's own libraries are stripped of section headers and ld refuses"; \
	    echo "        them; docs/BUILD.md says how the stubs are generated."; \
	    exit 1; \
	fi; \
	for hy in 0 1; do \
	    log=$(BUILD)/device-hy$$hy.log; mkdir -p $(BUILD); \
	    PATH="$$PWD/$$tc/bin:$$PATH" STAGING_DIR="$$PWD/$$tc" \
	    $(MAKE) -s BUILD=$(BUILD)/device-hy$$hy HYSTERIA=$$hy CC=$(CROSS_CC) \
	        MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB=dl/mipslib all \
	        >$$log 2>&1 \
	      && echo "  ok    every program builds for the router (mipsel, hysteria2 plane $$hy)" \
	      || { echo "  FAIL  the tree does not build for the router (mipsel, hysteria2 plane $$hy)"; \
	           tail -20 $$log; exit 1; }; \
	done; \
	a64="$(A64_TC)"; \
	if [ -z "$$a64" ]; then \
	    echo "  FAIL  no aarch64 toolchain under dl/tc-a64 — the AX3000T build was not checked"; \
	    exit 1; \
	fi; \
	if [ ! -f dl/a64lib/libmbedcrypto.so ]; then \
	    echo "  FAIL  dl/a64lib has no link stubs — see docs/BUILD.md, 'The same for aarch64'"; \
	    exit 1; \
	fi; \
	for hy in 0 1; do \
	    log=$(BUILD)/device-a64-hy$$hy.log; \
	    PATH="$$PWD/$$a64/bin:$$PATH" STAGING_DIR="$$PWD/$$a64" \
	    $(MAKE) -s BUILD=$(BUILD)/device-a64-hy$$hy HYSTERIA=$$hy CC=$(A64_CC) \
	        MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB=dl/a64lib all \
	        >$$log 2>&1 \
	      && echo "  ok    every program builds for the AX3000T (aarch64, hysteria2 plane $$hy)" \
	      || { echo "  FAIL  the tree does not build for aarch64 (hysteria2 plane $$hy)"; \
	           tail -20 $$log; exit 1; }; \
	done

# THE PMULL GHASH, RUN AND NOT ONLY COMPILED (2026-09-22).
#
# src/tls/ghash.c selects hardware GHASH by architecture and CPU capability; every arm64 router with
# the crypto extension takes PMULL. Until this target that path had been executed exactly once,
# by hand, on an AX3000T. So test-aead is built for aarch64 — statically, against the vendored
# mbedTLS compiled here into $(BUILD)/a64-mbedtls rather than inside vendor/, which check-vendor keeps
# untouched — and run under qemu-aarch64 with `-cpu max`, whose hwcaps carry AES and PMULL. The suite
# prints which GHASH it ran; a pass on the generic path would prove nothing about this one, so it is
# refused.
#
# Refuses to pass without the toolchain or without qemu, like check-device: a gate that skips what it
# cannot run says nothing about it. The image has qemu-user since the same day (docker/Dockerfile).
A64_CC  = aarch64-openwrt-linux-gcc
A64_TC  = $(patsubst %/bin/$(A64_CC),%,$(firstword $(wildcard dl/tc-a64/*/toolchain-*/bin/$(A64_CC))))
A64_ENV = PATH="$(CURDIR)/$(A64_TC)/bin:$$PATH" STAGING_DIR="$(CURDIR)/$(A64_TC)"
A64_MBED_SRC = $(wildcard vendor/mbedtls/library/*.c)
A64_MBED_OBJ = $(A64_MBED_SRC:vendor/mbedtls/library/%.c=$(BUILD)/a64-mbedtls/%.o)

$(BUILD)/a64-mbedtls/%.o: vendor/mbedtls/library/%.c
	@mkdir -p $(dir $@)
	@$(A64_ENV) $(A64_CC) -O1 -w -Ivendor/mbedtls/include -Ivendor/mbedtls/library -c -o $@ $<

$(BUILD)/a64-mbedtls/libmbedcrypto.a: $(A64_MBED_OBJ)
	@rm -f $@
	@$(A64_ENV) aarch64-openwrt-linux-ar rcs $@ $(A64_MBED_OBJ)

$(BUILD)/a64/test-aead: test/aead/test_aead.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC) $(BUILD)/a64-mbedtls/libmbedcrypto.a
	@mkdir -p $(dir $@)
	@$(A64_ENV) $(A64_CC) -static -std=c11 -O1 $(WARN) -Isrc -Ivendor/mbedtls/include -D_GNU_SOURCE \
	    -o $@ test/aead/test_aead.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC) $(BUILD)/a64-mbedtls/libmbedcrypto.a

check-arm64:
	@if [ -z "$(A64_TC)" ]; then \
	    echo "  FAIL  no aarch64 toolchain under dl/tc-a64 — the PMULL GHASH was not run"; exit 1; fi
	@command -v qemu-aarch64 >/dev/null 2>&1 || { \
	    echo "  FAIL  no qemu-aarch64 here — rebuild the image from docker/Dockerfile"; exit 1; }
	@$(MAKE) --no-print-directory $(BUILD)/a64/test-aead
	@out=$$(timeout $(TEST_TIMEOUT) qemu-aarch64 -cpu max $(BUILD)/a64/test-aead 2>&1); rc=$$?; \
	    [ $$rc -eq 0 ] || { printf '%s\n' "$$out" | tail -15; echo "  FAIL  test-aead on aarch64 (rc $$rc)"; exit 1; }; \
	    printf '%s\n' "$$out" | grep -q '^GHASH: pmull$$' || { \
	        echo "  FAIL  the aarch64 run did not take the PMULL path, so it tested nothing new"; exit 1; }; \
	    printf '%s\n' "$$out" | grep -q '^CHACHA: neon$$' || { \
	        echo "  FAIL  the aarch64 run did not take the NEON ChaCha20, so it tested nothing new"; exit 1; }; \
	    printf '%s\n' "$$out" | grep -q '^POLY1305: go$$' || { \
	        echo "  FAIL  the aarch64 run did not take Go's Poly1305, which every 64-bit router ships"; exit 1; }; \
	    n=$$(printf '%s\n' "$$out" | grep -c '^  ok '); \
	    [ "$$n" -gt 0 ] || { echo "  FAIL  test-aead under qemu asserted nothing at all"; exit 1; }; \
	    echo "  ok    AES-GCM on the PMULL GHASH and ChaCha20-Poly1305 on NEON agree with mbedTLS, $$n checks (aarch64 under qemu)"

# Both configurations compile, every time, and both are named here rather than left to whatever
# HYSTERIA happened to be on the command line.
#
# Each is what ships to somebody: one package is the REALITY client, the other carries the Hysteria2
# plane. Only the switch decides which, and a change that breaks the configuration nobody built would
# be found by the people running it rather than here.
#
# The second line was missing, and with it went more than a link: the plane's own modules — conn.c,
# qcrypto.c, shim.c, obfs.c — and the several hundred lines of lc-tunnel that sit behind
# `#if LC_HYSTERIA` were never handed to a compiler by `make check` at all. -Werror is worth exactly
# as much as the set of files it is run over.
#
# Each build gets its own directory. The switch is a preprocessor define and an object file does not
# record which defines made it, so building both into one tree would link objects compiled for the
# other configuration and call it a pass.

# The init script, parsed. Five hundred lines of shell that decide whether a household has an
# internet connection, and until this line nothing in the repository read them at all: `make check`
# could be green with a stray quote in the file that brings the router's interception up.
#
# Parsing is not running, and this makes no claim to be. It catches the class that costs the most for
# the least — the typo that turns a whole branch into something ash refuses at load — and it costs
# one process. `dash` because it is the POSIX shell that ships in this image; the target is busybox
# ash, which is the same language for everything this file uses. Anything relying on which shell it
# is would be a bug in the script either way.

# The ruleset that check-shell above can only parse. It renders lc_rules_up out of the real init
# script with nft and ip replaced by stubs, and reads what came out: the order the rules are inserted
# in, which ports are diverted, which family the node exemption uses, and that a refusal reaches the
# kernel with nothing. None of that is syntax, and all of it decides whether a household's traffic
# goes into the tunnel or straight out.
check-rules:
	@sh test/rules/test_rules.sh

# Explicit real-kernel gates; require the isolated nettest container described in BUILD.md.
# They are separate from host and SDK checks, which need neither NET_ADMIN nor nft modules.
.PHONY: check-kernel-rollback check-kernel-tproxy
check-kernel-rollback:
	$(PYTHON) test/rules/check_kernel.py --output "$(abspath $(BUILD)/kernel-rollback)"

check-kernel-tproxy:
	$(PYTHON) test/rules/check_kernel.py --output "$(abspath $(BUILD)/kernel-tproxy)" --require-tproxy

# Guest-kernel qualification needs QEMU TCG, cpio and the SDK host APK decoder.
# Fetch is explicit; the boot gate only accepts already cached, checksum-pinned inputs.
VM_CACHE ?= dl/vm-nettest
.PHONY: vm-nettest-fetch check-vm-tproxy vm-service-fetch vm-service-bundle check-vm-service
vm-nettest-fetch:
	$(PYTHON) test/rules/run_vm.py --cache "$(VM_CACHE)" --fetch-only --expected-release "$(OPENWRT_RELEASE)"

check-vm-tproxy:
	$(PYTHON) test/rules/run_vm.py --cache "$(VM_CACHE)" --apk-tool "$(SDK_DIR)/staging_dir/host/bin/apk" --output "$(abspath $(BUILD)/vm-tproxy)" --expected-release "$(OPENWRT_RELEASE)"

# Build peer/reference with the pinned Go toolchain; prepare a private bundle
# from real x86 SDK packages. The old fixture is controlled, not a past release.
VM_SERVICE_BUNDLE ?= $(abspath $(BUILD)/vm-service-bundle)
vm-service-fetch:
	$(PYTHON) test/rules/run_service_vm.py --cache "$(VM_CACHE)" --fetch-only --expected-release "$(OPENWRT_RELEASE)"

vm-service-bundle:
	@mkdir -p "$(BUILD)"
	CGO_ENABLED=0 $(GO127) build -o "$(abspath $(BUILD)/vm-service-peer)" test/rules/service-peer.go
	cd vendor/Xray-core && CGO_ENABLED=0 $(GO127) build -mod=readonly -o "$(abspath $(BUILD)/vm-service-xray)" ./main
	$(PYTHON) test/rules/prepare_service_vm.py --sdk "$(SDK_DIR)" --output "$(VM_SERVICE_BUNDLE)" --peer "$(abspath $(BUILD)/vm-service-peer)" --xray "$(abspath $(BUILD)/vm-service-xray)"

check-vm-service:
	$(PYTHON) test/rules/run_service_vm.py --cache "$(VM_CACHE)" --bundle "$(VM_SERVICE_BUNDLE)" --output "$(abspath $(BUILD)/vm-service)" --expected-release "$(OPENWRT_RELEASE)"

# The TCP memory the init script sizes for the whole router on every start: lc_tune_tcp out of the real
# script with sysctl stubbed, fed the two boxes it was measured on, and read back — times three and not
# times nine on a restart, a socket ceiling under the planes' 32 MB, a kernel's refusal that does not
# keep the tunnel down, a bad reading not kept as the kernel's sizing.
check-tune:
	@sh test/tune/test_tune.sh
# Which `workers` values the init script starts each plane with: REALITY takes 1..8 or auto; Hysteria2
# only 1, because each worker would be its own session and the node keeps one per subscription.
check-workers:
	@sh test/workers/test_workers.sh
# Whether the Hysteria2 plane parrots Chrome, from `option chrome_parrot` to the wire: the init
# script's reading of the option, where start_service passes it, and the size of the first datagram
# the binary sends with no -c, -c on and -c off — caught on a UDP socket where the node would be by
# test/parrot/firstdgram.c. On by default, as hysteria's client since 2.11.
$(BUILD)/test-firstdgram: test/parrot/firstdgram.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/parrot/firstdgram.c
check-parrot: $(BUILD)/lc-tunnel $(BUILD)/test-firstdgram
	@LC_TUNNEL=$(BUILD)/lc-tunnel LC_FIRSTDGRAM=$(BUILD)/test-firstdgram sh test/parrot/test_parrot.sh
check-shell:
	@sh -n package/files/lite-client.init \
	    && echo "  ok    the init script parses as a posix shell script" \
	    || { echo "  FAIL  the init script does not parse"; exit 1; }
	@sh -n test/rules/vm-guest.sh
	@sh -n test/rules/vm-service-init.sh
	@sh -n test/rules/vm-service-guest.sh

.PHONY: check-config
check-config: $(BUILD)/lc-tunnel
	$(MAKE) --no-print-directory BUILD=$(BUILD)/$(if $(filter 1,$(HYSTERIA)),without-hysteria,with-hysteria) \
	    HYSTERIA=$(if $(filter 1,$(HYSTERIA)),0,1) \
	    $(BUILD)/$(if $(filter 1,$(HYSTERIA)),without-hysteria,with-hysteria)/lc-tunnel
	LC_TUNNEL_HY0=$(abspath $(if $(filter 0,$(HYSTERIA)),$(BUILD),$(BUILD)/without-hysteria)/lc-tunnel) \
	    LC_TUNNEL_HY1=$(abspath $(if $(filter 1,$(HYSTERIA)),$(BUILD),$(BUILD)/with-hysteria)/lc-tunnel) \
	    $(PYTHON) -m unittest discover -s test/config -p 'test_*.py' -v
# Nothing under src/ outside cmd/ writes to a stream of its own.
#
# ⚠️ THIS EXISTS BECAUSE THE RULE IT GUARDS WAS BROKEN TWICE IN TWO DAYS, both times while the rule
# itself was written down in a comment a few lines away and believed. A library that prints does two
# wrong things at once: it decides for its caller where the words go, and — the expensive half — it
# writes them with printf, which hands a line to the descriptor in as many pieces as the format has.
# lc-tunnel runs several workers on ONE stdout and ONE stderr, procd having given the same
# descriptors to every fork, so those pieces interleave. Measured on a live router: 20 of 44 records
# shredded, and 0 of 44 once each line was built whole and written once.
#
# The check cannot see that tearing — it needs procd, and no gate here has one, which is written up
# at length in test/seam. What it CAN do is keep the shape that made the tearing possible from coming
# back, and that is the half that kept regressing: the fault was never subtle, it was simply nobody's
# job to notice. `note()` in cmd/lc-tunnel/main.c owns the program's voice; a library hands its
# caller a reason and lets the caller speak.
#
# Comment lines are dropped before looking, because this very Makefile and both of those files
# discuss `fprintf` and `stderr` in prose. A check that reads the explanation as the offence would
# be green only while nobody explained anything.
#
# Headers are looked at too, and not as an afterthought: a `static inline` in a .h is library code
# that ends up compiled into every caller, which is the one place where a stray printf would spread
# rather than sit still.
QUIET_PAT = \b(printf|fprintf|vfprintf|fputs|fputc|putchar|perror)[[:space:]]*\(
QUIET_SRC = $(shell find src \( -name '*.c' -o -name '*.h' \) -not -path 'src/cmd/*')
check-quiet-lib:
	@hits=$$(grep -nHE '$(QUIET_PAT)' $(QUIET_SRC) | grep -v '^[^:]*:[0-9]*:[[:space:]]*[*/]'); \
	if [ -n "$$hits" ]; then \
	    echo "  FAIL  a file under src/ outside cmd/ writes to a stream of its own"; \
	    echo "$$hits"; \
	    exit 1; \
	else echo "  ok    no library file under src/ prints on its own account"; fi
# Every counter the tunnel keeps is both moved and shown.
#
# ⚠️ THE SUMMARY IS THE ONLY ACCOUNT ANYBODY GETS OF A ROUTER THEY CANNOT SEE, and it has been wrong
# in three different ways in three weeks: numbers printed on a plane that cannot move them, a
# direction counted going down and not going up (twenty megabytes of upload reported as twenty
# kilobytes), and a field — `vision_pad` — declared, named after a measurement, and touched by
# nothing at either end. All three passed every test in this tree, because a counter is not a return
# value and nothing here reads a log.
#
# This catches the last shape of the three and only that one: a field that is never written has no
# number to give, and a field that is never printed gives its number to nobody. Both are decidable
# with a grep, which is the whole reason to do it here rather than trust a reviewer to notice a
# missing line in a struct of twenty-one.
#
# The other two shapes are NOT decidable this way and are not claimed: whether a counter can move on
# the plane in use, and whether the thing being counted has a second half, both need someone to read
# the code. The way that was found is written up in the memory of this project — list every counter
# against its increment sites, rather than reading the summary line by line, which is how two of them
# were missed on the first pass.
#
# ⚠️ THE awk RESETS ITS BUFFER AT EVERY `static struct {`, so only the block that actually ends at
# `} stats;` is handed on. Written the obvious way — set a flag at the first opening and print until
# the closing line — it takes the FIRST struct in the file and swallows everything down to `} stats;`
# along with it, which is a false failure on some other struct's fields the day one is added above.
# Not a hypothetical: that is exactly what the first attempt at this list did, and the fields of two
# other structs in the output are what showed it.
#
# ⚠️ AND AN EMPTY LIST IS A FAILURE, NOT A PASS. The loop below runs once per counter it found, so
# the day the struct is renamed, or its fields stop matching the pattern, it runs zero times and —
# as it stood — printed its ok line over nothing. It now counts, refuses zero, and says the number.
check-counters:
	@f=src/cmd/lc-tunnel/main.c; bad=0; n=0; \
	for c in $$(awk '/^static struct \{/{b=""; s=1} s{b=b $$0 "\n"} /^} stats;/{printf "%s", b; exit}' $$f \
	    | grep -oE '^[[:space:]]*uint64_t [a-z_0-9, ]+;' | sed 's/.*uint64_t //; s/;//' \
	    | tr ',' '\n' | tr -d ' ' | grep -v '^$$'); do \
	    n=$$((n + 1)); \
	    if [ "$$(grep -cE "stats\.$$c *(\+\+|\+=|= )" $$f)" = 0 ]; then \
	        echo "  FAIL  stats.$$c is declared but never moved"; bad=1; fi; \
	    if [ "$$(grep -cE "\(unsigned long long\)stats\.$$c\b" $$f)" = 0 ]; then \
	        echo "  FAIL  stats.$$c is counted but never printed"; bad=1; fi; \
	done; \
	if [ $$n = 0 ]; then \
	    echo "  FAIL  no counters found in the stats struct of $$f: the list is broken, not the counters"; \
	    exit 1; fi; \
	[ $$bad = 0 ] && echo "  ok    all $$n counters the tunnel keeps are both moved and printed" || exit 1
# ⚠️ EVERY PATH THAT OPENS A STREAM SENDS WHAT THE CLIENT ALREADY SAID, and one of them did not.
#
# The UDP listener stores a datagram before there is anywhere to write it (`pend_put`), because the
# stream does not exist yet. Whoever opens the stream owes it the request, and the request owes it
# the datagram. advance_handshake once did that in two statements; spare_bind — the path every request
# takes with the pool on (-P), which was then the default — had only the first, so the first datagram
# of every UDP session was swallowed. Measured against a real Xray on the local stand: request header
# out, nothing behind it, resolver times out.
#
# The two statements are one call now, request_start, and it is what hands a datagram session to
# udp_pump. So the invariant has three halves, each mechanical: every function that opens a REALITY
# stream (`->st = ST_OPEN` outside the hy_ plane) calls request_start; request_start reaches udp_pump;
# and nothing but request_header builds a VLESS request, so no path can write one around them.
#
# Checked structurally rather than by a test because the thing that failed is a whole session on an
# event loop: to exercise it a suite would have to build a tunnel, a spare, a listener and a node.
# Comment lines are skipped: a paragraph that MENTIONS a call must not be able to satisfy the check
# for a function that does not make it.
check-pend:
	@f=src/cmd/lc-tunnel/main.c; \
	scan='/^[ \t]*\*/{next} /^[ \t]*\/\*/{next} /^[a-zA-Z_].*\(/{fn=$$0}'; \
	miss=$$(awk "$$scan"' \
	             /^[ \t]+.*->st = ST_OPEN;/{if (fn!="" && fn !~ /hy_/) o[fn]=1} \
	             /^[ \t]+.*request_start\(/{if (fn!="") p[fn]=1} \
	             END{for (k in o) if (!(k in p)) print k}' $$f); \
	[ -z "$$miss" ] || { echo "$$miss" | sed 's/^/  FAIL  opens a stream and never writes the request: /'; exit 1; }; \
	awk "$$scan"' /^[ \t]+.*udp_pump\(/{if (fn ~ /^static int request_start\(/) ok=1} END{exit !ok}' $$f \
	    || { echo "  FAIL  request_start no longer hands a datagram session to udp_pump"; exit 1; }; \
	stray=$$(awk "$$scan"' /^[ \t]+.*lc_vless_request(_udp)?\(/{if (fn !~ /^static int request_header\(/) print fn}' $$f); \
	[ -z "$$stray" ] || { echo "$$stray" | sed 's/^/  FAIL  builds a VLESS request outside request_header: /'; exit 1; }; \
	echo "  ok    every path that opens a stream writes the request with what the client already said"

# The request's wait for the client's first bytes is the reference's half second, held to the
# vendored line for the reason check-retry gives: a copied constant is the one that rots.
check-request:
	@v=vendor/Xray-core/proxy/vless/outbound/outbound.go; f=src/cmd/lc-tunnel/main.c; \
	ref=$$(grep -oE 'ReadMultiBufferTimeout\(time\.Millisecond \* [0-9]+\)' $$v | grep -oE '[0-9]+'); \
	[ -n "$$ref" ] || { echo "  FAIL  the reference's first-payload wait is not where this gate looks: $$v"; exit 1; }; \
	mine=$$(grep -oE '^#define REQUEST_WAIT_MS +[0-9]+u' $$f | grep -oE '[0-9]+'); \
	[ "$$ref" = "$$mine" ] && echo "  ok    the request waits for the client's first bytes as long as the reference" \
	    || { echo "  FAIL  reference waits [$$ref ms], this client [$$mine ms]"; exit 1; }

# ⚠️ THE TWO RETRY NUMBERS ARE THE REFERENCE'S, AND NOTHING BUT THIS SAYS SO.
#
# DIAL_TRIES and DIAL_STEP_MS are `retry.ExponentialBackoff(5, 200)` in Xray's VLESS outbound. A
# constant copied from upstream and then left alone is the failure this tree keeps finding — the
# prose beside it goes on claiming a value the code no longer has, or upstream moves and nobody
# looks — so the claim is checked against the vendored line rather than asserted in a comment.
#
# Structural for the reason check-pend is: exercising the retry needs a node that refuses fast,
# a loop, a listener and a clock. What can be held mechanically is the part that actually rots.
.PHONY: check-reality-version
check-reality-version:
	@ref=$$(sed -n 's/^[[:space:]]*Version_[xyz] byte = \([0-9]*\).*$$/\1/p' vendor/Xray-core/core/core.go | tr '\n' ' '); \
	mine=$$(sed -n 's/^#define LC_REALITY_VERSION_[A-Z]* \([0-9]*\)u$$/\1/p' src/reality/reality.h | tr '\n' ' '); \
	[ -n "$$ref" ] && [ "$$ref" = "$$mine" ] \
	    || { echo "  FAIL  REALITY client version differs: Xray [$$ref], client [$$mine]"; exit 1; }; \
	for tool in lc-fetch lc-probe lc-xfetch lc-tunnel; do \
	    for field in '0 MAJOR' '1 MINOR' '2 PATCH'; do \
	        set -- $$field; \
	        grep -Fq "reality.version[$$1] = LC_REALITY_VERSION_$$2;" src/cmd/$$tool/main.c || exit 1; \
	    done; \
	done; \
	echo "  ok    all REALITY entry points report the pinned Xray version"

check-retry:
	@v=vendor/Xray-core/proxy/vless/outbound/outbound.go; f=src/cmd/lc-tunnel/main.c; \
	got=$$(grep -oE 'retry\.ExponentialBackoff\([0-9]+, *[0-9]+\)' $$v | head -1 \
	    | grep -oE '[0-9]+' | tr '\n' ' '); \
	[ -n "$$got" ] || { echo "  FAIL  the reference's retry call is not where this gate looks: $$v"; exit 1; }; \
	mine=$$(grep -oE '^#define DIAL_(TRIES|STEP_MS) +[0-9]+u' $$f | grep -oE '[0-9]+' | tr '\n' ' '); \
	[ "$$got" = "$$mine" ] && echo "  ok    the dial retries as many times and as slowly as the reference" \
	    || { echo "  FAIL  reference retry is [$$got], this client is [$$mine]"; exit 1; }

# ⚠️ THE POOL'S NUMBERS ARE THE REFERENCE'S TOO, and this tree once replaced both with its own.
#
# A pooled connection is good for `time.Minute * 2` from its dial, and the dialler sleeps
# `time.Millisecond * 200` after handing one over — two literals on the two lines of the pre-connect
# goroutine in Xray's VLESS outbound. `testpre` has no default written anywhere: it is a Go zero value,
# so the pool's default here is held to zero by reading the initialiser. Same reasoning as check-retry.
check-pool:
	@v=vendor/Xray-core/proxy/vless/outbound/outbound.go; f=src/cmd/lc-tunnel/main.c; \
	exp=$$(grep -E 'h\.preConns <- ' $$v | grep -oE 'time\.Minute \* [0-9]+' | grep -oE '[0-9]+$$'); \
	slp=$$(grep -A1 -E 'h\.preConns <- ' $$v | grep -oE 'time\.Millisecond \* [0-9]+' | grep -oE '[0-9]+$$'); \
	[ -n "$$exp" ] && [ -n "$$slp" ] || { echo "  FAIL  the reference's pre-connect lines are not where this gate looks: $$v"; exit 1; }; \
	mexp=$$(grep -oE '^#define SPARE_EXPIRE_MS +[0-9]+u' $$f | grep -oE '[0-9]+'); \
	mslp=$$(grep -oE '^#define SPARE_SLEEP_MS +[0-9]+u' $$f | grep -oE '[0-9]+'); \
	grep -qE '^\} spare = \{ \.want = 0u \};' $$f || { echo "  FAIL  the pool is not off by default, and testpre's zero value is"; exit 1; }; \
	[ "$$((exp * 60000))" = "$$mexp" ] && [ "$$slp" = "$$mslp" ] \
	    && echo "  ok    the pool holds a connection as long, sleeps as long and starts as off as the reference" \
	    || { echo "  FAIL  reference pool is [$$((exp * 60000)) ms, $$slp ms], this client is [$$mexp ms, $$mslp ms]"; exit 1; }

# The ceiling on a server's RSA key, checked against the reference that set it. Two lines of code in
# certverify.c, and the kind that rots quietly: nothing in this tree ever presents a key that large,
# so no test can reach the refusal without inventing a certificate whose only purpose is to be
# enormous. What CAN rot is the number, and it is the reference's.
check-rsa:
	@v=vendor/utls/handshake_client.go; f=src/tls/certverify.h; \
	ref=$$(grep -oE '^const defaultMaxRSAKeySize = [0-9]+' $$v | grep -oE '[0-9]+'); \
	[ -n "$$ref" ] || { echo "  FAIL  the reference's RSA ceiling is not where this gate looks: $$v"; exit 1; }; \
	mine=$$(grep -oE '^#define LC_MAX_RSA_BITS +[0-9]+u' $$f | grep -oE '[0-9]+'); \
	[ -n "$$mine" ] || { echo "  FAIL  LC_MAX_RSA_BITS is gone"; exit 1; }; \
	grep -q 'LC_MAX_RSA_BITS' src/tls/certverify.c \
	    || { echo "  FAIL  nothing applies the ceiling any more"; exit 1; }; \
	[ "$$ref" = "$$mine" ] && echo "  ok    the RSA ceiling is the reference's $$ref bits, and something applies it" \
	    || { echo "  FAIL  reference ceiling is $$ref bits, this client says $$mine"; exit 1; }

# THE REASONS A CLIENT CLOSES WITH ARE QUIC-GO'S OWN WORDS. patches/ngtcp2/0033 records, at every
# check a server's packet can fail, the reason quic-go's CONNECTION_CLOSE carries for it; the ones
# quic-go's own packages can be run for are held by tools/qgovec and test/ngpatch, and this holds
# every one of them to the text of vendor/quic-go, format and all — see tools/qgoreasons.
check-qgo-reasons:
	@cd tools/qgoreasons && go build -o $(abspath $(BUILD))/qgoreasons . && cd $(CURDIR) && \
	  $(abspath $(BUILD))/qgoreasons

# ⚠️ HOW OFTEN THIS CLIENT WRITES WHILE READING, WHICH NO TEST WOULD MISS IF IT CHANGED.
#
# ngtcp2 only QUEUES an acknowledgement; the frame goes out when this program writes, so the cadence
# of acknowledgements is the cadence of the write path inside the receive loop. It was once one write
# per turn — one answer per 38.7 arrivals, measured — then one per two datagrams, taken from the
# wrong quic-go constant (packetsBeforeAck, which queues an ACK rather than sends one). The
# reference's loop reads at most maxPacketsToProcess = 32 queued packets before it sends
# (vendor/quic-go/connection.go:1021-1056), and that is the number src/quic/conn.c holds.
#
# The cadence is observable only against a real peer, so its shape is pinned here:
#
#   1. the write still happens INSIDE the receive path, not only after it — and it looks for the
#      COMPARISON, `>= LC_QRX_PER_TURN`, not for the name: an earlier version took the last line
#      mentioning the constant, which was a comment inside the same function, and deleting the whole
#      block left the gate green;
#   2. the number equals the reference's, read out of the vendored quic-go, so a re-vendored quic-go
#      that changes it fails here with the new number named.
check-ack:
	@v=vendor/quic-go/connection.go; f=src/quic/conn.c; \
	ref=$$(grep -oE '^const maxPacketsToProcess = [0-9]+' $$v | grep -oE '[0-9]+'); \
	[ -n "$$ref" ] || { echo "  FAIL  the reference's per-turn packet bound is not where this gate looks: $$v"; exit 1; }; \
	grep -q "maxPacketsToProcess = $$ref" $$f \
	    || { echo "  FAIL  conn.c argues from a reference bound that is no longer $$ref"; exit 1; }; \
	mine=$$(grep -oE '^#define LC_QRX_PER_TURN +[0-9]+u' $$f | grep -oE '[0-9]+'); \
	[ -n "$$mine" ] || { echo "  FAIL  LC_QRX_PER_TURN is gone"; exit 1; }; \
	step=$$(grep -n '^int lc_qconn_step' $$f | cut -d: -f1); \
	use=$$(grep -nE '^[[:space:]]*if \(\+\+[a-z_]+ >= LC_QRX_PER_TURN\) \{$$' $$f | tail -1 | cut -d: -f1); \
	[ -n "$$step" ] && [ -n "$$use" ] && [ "$$use" -gt "$$step" ] \
	    || { echo "  FAIL  nothing writes inside the receive loop: the cadence is back to one per turn"; exit 1; }; \
	[ "$$mine" = "$$ref" ] \
	    || { echo "  FAIL  this client writes after $$mine datagrams, the reference after $$ref"; exit 1; }; \
	echo "  ok    the write path runs inside the receive loop after $$mine datagrams, the reference's bound"

# EVERY ALERT NUMBER THIS CLIENT SENDS IS THE REFERENCE'S NUMBER FOR THAT NAME. A refusal is chosen
# with care at each site and then leaves as whatever integer the constant holds, so a wrong constant
# defeats every site at once and every test that compares against the same constant agrees with it.
# That happened: LC_ALERT_UNSUPPORTED_CERTIFICATE was 48 from the day it was written, which is
# unknown_ca; the reference's is 43 (vendor/utls/alert.go:38, :43). Names are matched with the
# underscores dropped and case folded — LC_ALERT_BAD_RECORD_MAC against alertBadRecordMAC.
check-alerts:
	@a=src/tls/alert.h; v=vendor/utls/alert.go; bad=0; n=0; \
	for pair in $$(sed -nE 's/^#define LC_ALERT_([A-Z_]+) ([0-9]+)u$$/\1=\2/p' $$a); do \
	    name=$${pair%=*}; num=$${pair#*=}; n=$$((n + 1)); \
	    key=$$(printf '%s' "$$name" | tr -d _ | tr 'A-Z' 'a-z'); \
	    ref=$$(sed -nE 's/^[[:space:]]*alert([A-Za-z0-9]+)[[:space:]]+alert = ([0-9]+)$$/\1 \2/p' $$v | \
	           awk -v k="$$key" 'tolower($$1) == k { print $$2 }'); \
	    if [ -z "$$ref" ]; then echo "  FAIL  LC_ALERT_$$name names no alert in $$v"; bad=1; \
	    elif [ "$$ref" != "$$num" ]; then echo "  FAIL  LC_ALERT_$$name is $$num, the reference's is $$ref"; bad=1; fi; \
	done; \
	[ $$n -gt 0 ] || { echo "  FAIL  no LC_ALERT_ numbers found in $$a"; exit 1; }; \
	[ $$bad -eq 0 ] || exit 1; \
	echo "  ok    all $$n alert numbers in $$a are the reference's (vendor/utls/alert.go)"

# THE CRYPTO DATA A CLIENT ACCEPTS, which the reference bounds at sixteen kilobytes on every
# encryption level (MaxCryptoStreamOffset, vendor/quic-go/internal/protocol/params.go:86-88) and
# upstream ngtcp2 at 64 and 256 — patches/ngtcp2/0012 gives ngtcp2 the reference's number. Read out
# of the PATCHED copy, since that is what is compiled, and out of the vendored quic-go, so a
# re-vendored quic-go with a new bound fails here with the number named. The expression is
# evaluated rather than matched: `16 * (1 << 10)` there, `(16 * 1024)` here.
check-crypto: $(NGTCP2_STAMP)
	@v=vendor/quic-go/internal/protocol/params.go; f=$(NGTCP2_DIR)/lib/ngtcp2_conn.c; \
	e=$$(sed -nE 's/^const MaxCryptoStreamOffset = ([0-9]+) \* \(1 << ([0-9]+)\)$$/\1 \2/p' $$v); \
	set -- $$e; [ $$# -eq 2 ] || { echo "  FAIL  the reference's CRYPTO bound is not where this gate looks: $$v"; exit 1; }; \
	ref=$$(( $$1 << $$2 )); \
	for lvl in INITIAL HANDSHAKE 1RTT; do \
	    got=$$(grep -oE "^#define NGTCP2_MAX_$${lvl}_CRYPTO_OFFSET \([0-9]+ \* 1024\)" $$f | grep -oE '[0-9]+ \*' | grep -oE '[0-9]+'); \
	    [ -n "$$got" ] || { echo "  FAIL  NGTCP2_MAX_$${lvl}_CRYPTO_OFFSET is not where this gate looks: $$f"; exit 1; }; \
	    [ $$(( got * 1024 )) -eq $$ref ] \
	        || { echo "  FAIL  ngtcp2 accepts $$(( got * 1024 )) bytes of CRYPTO data at $$lvl, the reference $$ref"; exit 1; }; \
	done; \
	echo "  ok    ngtcp2 accepts at most $$ref bytes of CRYPTO data at every level, the reference's bound"

# ⚠️ A POINTER INTO A FILE THAT NO LONGER EXISTS READS AS A CITATION AND ANSWERS NOTHING.
#
# Found on 2026-09-07, twice, by looking rather than by any check: quic/conn.c sent the reader to
# `quic/revive.h`, which went out with the machinery it documented, and ghash/inner.h sent them to
# `src/tls/ghash.h`, which has never existed at all. Both had stood since the code around them was
# rewritten, and both cost the same thing — the reader spends the search before learning the answer
# is not there, which is worse than no pointer, because no pointer promises nothing.
#
# The sieve cannot catch these: it checks references into vendor/, and these point at us. Only our
# own module directories are matched, so vendor tails like `lib/ngtcp2_conn.c` or `library/gcm.c`
# are not mistaken for ours.
check-refs:
	@bad=$$(grep -rhoE '\b(src/)?(core|net|tls|cert|fp|reality|vless|quic|ghash)/[a-z0-9_]+\.[ch]\b' \
	    src test --include='*.c' --include='*.h' | sed 's|^src/||' | sort -u \
	    | while read f; do [ -f "src/$$f" ] || echo "$$f"; done); \
	[ -z "$$bad" ] && echo "  ok    every pointer at one of our own files leads to one" \
	    || { echo "$$bad" | sed 's|^|  FAIL  named in a comment but not in the tree: |'; exit 1; }

# ⚠️ AND A NAME IS A POINTER TOO. check-refs above asks the question of FILES; this asks it of the
# identifiers, which is where the same defect actually lives — a comment citing `lc_fp_supported`
# beside the `lc_fpt_supported` it means, or `LC_H3_PAD_MIN` where the constants are
# LC_PAD_AUTH_MIN/MAX in a different header. Both were here, both read as citations, and both sent
# the reader to a grep that returns one line: the comment itself. Found 2026-09-12 by asking this
# question mechanically for the first time; 630 of our identifiers, two of them naming nothing.
#
# WHAT COUNTS AS CODE: a line whose first non-space character is not `*`, `//` or `/*`. Block
# comments in this tree are continued with ` * `, so the split is exact for them, and a trailing
# comment on a code line is counted as code — which can only MISS a dead name, never invent one. A
# gate that invents work gets switched off.
#
# TRAILING-UNDERSCORE NAMES ARE WILDCARDS (`LC_FPT_*`, `LC_GROUP_*`), not identifiers, and are
# skipped by shape.
#
# ⚠️ THE THREE BELOW ARE MENTIONED BECAUSE THEY ARE GONE, and that is the whole point of the
# paragraphs they sit in: lc_set_blocking is named by the rule that now holds without it,
# lc_vless_udp_next by the contract that used to borrow its wording, LC_STALL_MS by the account of
# the invented stall timer that was removed. They are listed here rather than allowed by shape,
# because "mentioned as gone" and "misspelt" look identical to a grep — and a list of three that
# has to be edited deliberately is the cheapest way to keep the difference visible.
check-names:
	@gone='^(lc_set_blocking|lc_vless_udp_next|LC_STALL_MS)$$'; \
	all=$$(grep -rhoE 'lc_[a-z0-9_]+|LC_[A-Z0-9_]+' src --include='*.c' --include='*.h' | sort -u); \
	code=$$(grep -rhvE '^[[:space:]]*(\*|//|/\*)' src --include='*.c' --include='*.h' \
	    | grep -oE 'lc_[a-z0-9_]+|LC_[A-Z0-9_]+' | sort -u); \
	bad=$$(echo "$$all" | grep -vxF "$$code" | grep -vE '_$$' | grep -vE "$$gone" || true); \
	[ -z "$$bad" ] && echo "  ok    every lc_/LC_ name a comment cites exists in the code" \
	    || { echo "$$bad" | sed 's|^|  FAIL  cited in a comment and defined nowhere: |'; exit 1; }

# ⚠️ A CITATION INTO vendor/ THAT POINTS PAST THE END OF THE FILE IS THE SAME LIE ONE LAYER OUT.
#
# 473 of them carry a line number, and the number is the part that rots: re-vendoring moves every
# line below an insertion, and nothing in this tree reads them — the sieve pairs them, but a pair
# whose target is gone comes back as a finding about our code rather than about the pointer. This
# asks the cheap half of the question, which is also the half that fails first: the file exists and
# it is at least that long. It cannot ask whether the line still says what the comment claims; the
# sieve's acceptance pass is what does that, and it costs hours rather than a second.
#
# patches/ is read for the same reason as src/: the comments inside patches/ngtcp2/*.patch are
# compiled into the client, and the prose headers of those patches are the whole account of why our
# ngtcp2 differs from the pinned upstream. A citation rotting there is invisible otherwise — the
# patched tree lives in build/ and nothing keeps it.
# Clean when written (2026-09-12), so what this buys is the day vendor/ is bumped.
# ⚠️ FOUR FORMS OF CITATION USED TO BE INVISIBLE HERE. What stood in this recipe matched
# `vendor/path/file.go` and a line number, and nothing else: a path without the vendor/
# prefix, a bare file name, the second number of a comma list, and a name with no line at all
# all passed unchecked. tools/cites/check.sh reads all five forms, fails on a citation that
# cannot be right, and counts the ones no machine can resolve — see its header.
#
# ⚠️ AND AN ADDRESS THAT LANDS IS NOT A CLAIM THAT HOLDS (2026-09-24). "It cannot ask whether the
# line still says what the comment claims", above, was taken as the end of what a machine can do,
# and about a hundred and fifty citations had drifted off what they described with every one of
# them an address: the "ten moved line numbers in client.c" of the audit of 23 September turned
# out to be the visible part of that. tools/cites/claims asks what CAN be asked without
# understanding the sentence — whether the code a comment quotes, the function it names, the number
# on its line and the function below it are where the citation says — and fails on any that is
# not. Its own test runs first: a checker that has quietly stopped finding anything passes every
# tree, which is how the gates that were empty stayed green. See the header of its main.go for
# what it still does not see.
# THE ONE LIST OF WHERE THIS CLIENT IS NOT ITS REFERENCE, held to the code: DIVERGENCES.md names
# each known divergence, the code marks each one where it is (`DIVERGES: <id>`), and this fails on a
# mark without a row or a row without a mark — so a divergence ported is a row struck off, and one
# found is a row added, or the gate says which. It prints the count on every run. The maintainer
# asked for it on 2026-09-26: "it should be easy and simple to understand where we diverge".
check-divergences:
	@sh tools/divergences/check.sh

check-cites:
	@sh tools/cites/check.sh
	@cd tools/cites/claims && { go test -count=1 . > $(abspath $(BUILD))/claims-test.log 2>&1 \
	  && echo "  ok    tools/cites/claims finds each misplaced citation it is shown, and passes the right ones" \
	  || { echo "  FAIL  tools/cites/claims's own test — the checker below proves nothing"; \
	       tail -20 $(abspath $(BUILD))/claims-test.log; exit 1; }; }
	@cd tools/cites/claims && go run .

# ⚠️ TWO SNAPSHOTS THAT AGREE WITH EACH OTHER AND GO STALE TOGETHER.
#
# test/fphello already builds the SHIPPED table and compares the hello byte for byte against
# test/fphello/reference_firefox.h, so the table is not unchecked. Both are snapshots of ONE uTLS
# revision, and that file's own header states the contract nothing enforced: "uTLS is pinned to the
# revision Xray-core pins ... Raising either pin means regenerating this file and the packed table
# together". Re-vendor Xray-core with a newer uTLS and the pair stays consistent WITH EACH OTHER
# while both stop being what the reference client puts on the wire: the test passes, and the hello
# is a Firefox that no longer exists. That is the exact failure the whole fingerprint subsystem is
# built against — it connects, it carries traffic, and it is identifiable on the wire.
#
# Two questions, and they fail for different reasons and with different messages:
#
#   1. the capture tool and the reference still pin the SAME uTLS. tools/fp/go.mod is what `fp` is
#      built against; vendor/Xray-core/go.mod is what the client being imitated is built against.
#      Only the second moves when Xray-core is re-vendored, and nothing else in this tree looks at
#      it — a divergence here means the frozen vector stopped being the reference's message while
#      every test that reads it still passes.
#   2. the shipped table is byte for byte what that uTLS produces TODAY. This is the half the old
#      comment above said was impossible, and it stopped being impossible when the ECH candidate
#      list moved off the rendered hello; it is what catches a bump that moves a literal extension
#      body, which is invisible to a comparison of two frozen files against each other.
#
# ⚠️ AND A THIRD THING THIS GATE DOES NOT COVER, said here because the wording above invites the
# wrong reading. There are three uTLS in play, not two: the module `tools/fp` builds against (the
# cache, at the revision Xray pins — that IS what this gate pairs), and `vendor/utls/`, which is a
# SEPARATE checkout and the one every `vendor/utls/…:N` citation in this tree points at, the sieve
# reads, and `src/fp/` copied its tables from. tools/fp/go.mod carries no `replace` to it, unlike
# tools/salamander and tools/vendorcap/qstand which do point at their vendored trees. The two are
# five months apart on purpose and docs/BUILD.md "Pinned revisions" states the consequence. That the
# checkout still SITS at the recorded revision is no longer unchecked either: check-vendor below
# asks it of every tree the table gives a revision for, on every run. zlib and bearssl are source
# drops with no .git and nothing to compare; the table names a release for zlib and says plainly
# that bearssl's revision is not recoverable.
#
# `tr -d '\r'` is not defensive tidiness. vendor/Xray-core/go.mod is checked out with CRLF and
# tools/fp/go.mod with LF, so the two pins differ by a byte nobody can see, and the first run of this
# gate failed with a message naming two identical-looking strings. Worse, the host lied about it:
# grep from Git Bash strips CR in text mode, so `cat -A` on the host showed a clean line and only the
# Linux container disagreed. The neighbouring gates are immune by accident rather than by care —
# check-rsa, check-ack and check-retry reduce the vendored line to digits, where a CR cannot survive.
# Anything comparing a vendored TOKEN has to do this.
check-fingerprint: $(BUILD)/fp $(BUILD)/fp-hysteria
	@cd tools/fp && $(GO127) test -count=1 ./...
	@cd tools/fp && go test -count=1 -mod=readonly -modfile=hysteria.mod ./...
	@ours=$$(grep -oE 'utls v[0-9][^ ]*' tools/fp/hysteria.mod | head -1 | tr -d '\r'); \
	ref=$$(grep -oE 'utls v[0-9][^ ]*' vendor/quic-go/go.mod | head -1 | tr -d '\r'); \
	[ -n "$$ours" ] && [ "$$ours" = "$$ref" ] \
	    && echo "  ok    Hysteria capture and quic-go pin the same uTLS ($$ours)" \
	    || { echo "  FAIL  Hysteria fingerprint dependency differs from quic-go"; exit 1; }
	@ours=$$(grep -oE 'utls v[0-9][^ ]*' tools/fp/go.mod | head -1 | tr -d '\r'); \
	ref=$$(grep -oE 'utls v[0-9][^ ]*' vendor/Xray-core/go.mod | head -1 | tr -d '\r'); \
	[ -n "$$ours" ] && [ -n "$$ref" ] \
	    || { echo "  FAIL  a uTLS pin is not where this gate looks: tools/fp/go.mod, vendor/Xray-core/go.mod"; exit 1; }; \
	[ "$$ours" = "$$ref" ] \
	    && echo "  ok    the capture tool and Xray-core pin the same uTLS ($$ours)" \
	    || { echo "  FAIL  fp is built against $$ours and the reference against $$ref: the capture is no longer the reference's hello"; exit 1; }
	@{ $(call fp_capture,$(BUILD)/fp-gate.fpt,$(BUILD)/fp-gate,firefox) ; } >/dev/null
	@cmp -s $(BUILD)/fp-gate.fpt package/files/fingerprint.fpt \
	    && echo "  ok    the shipped table is what today's uTLS produces" \
	    || { echo "  FAIL  package/files/fingerprint.fpt is not what uTLS produces now: run \`make fingerprint\`, and regenerate test/fphello/reference_firefox.h from the same uTLS in the same commit"; exit 1; }
	@{ $(call fp_capture,$(BUILD)/fp-gate-chrome.fpt,$(BUILD)/fp-gate-chrome,chrome) ; } >/dev/null
	@cmp -s $(BUILD)/fp-gate-chrome.fpt test/fphello/chrome.fpt \
	    && echo "  ok    the Chrome table is what today's uTLS produces, in its parrot's own order" \
	    || { echo "  FAIL  test/fphello/chrome.fpt is not what uTLS produces now: run \`make fingerprint\`"; exit 1; }
	@$(BUILD)/fp-hysteria speccheck -spec $(QUIC_SPEC) -copy tools/fp/quic.go >/dev/null \
	    && echo "  ok    tools/fp's copy of the fork's Chrome QUIC spec is the fork's, token for token" \
	    || { $(BUILD)/fp-hysteria speccheck -spec $(QUIC_SPEC) -copy tools/fp/quic.go; echo "  FAIL  tools/fp/quic.go no longer copies $(QUIC_SPEC)"; exit 1; }
	@$(BUILD)/fp-hysteria check -fp chrome-quic -sni $(FP_SNI) -shuffled -parrots $(FP_HYSTERIA_PARROTS) -spec $(QUIC_SPEC) >/dev/null \
	    && echo "  ok    the Chrome QUIC hello survives reference -> table -> rebuild" \
	    || { echo "  FAIL  the chrome-quic table does not carry the reference's hello"; exit 1; }
	@{ $(call fp_capture_quic,$(BUILD)/fp-gate-cq.h,$(BUILD)/fp-gate-cq) ; } >/dev/null
	@cmp -s $(BUILD)/fp-gate-cq.h src/quic/chrome_hello.h \
	    && echo "  ok    the hysteria plane's compiled-in hello table is what the fork's spec produces today" \
	    || { echo "  FAIL  src/quic/chrome_hello.h is not what the fork's spec produces now: run \`make fingerprint\`"; exit 1; }

# ⚠️ "PINNED REVISIONS" WAS PROSE, AND PROSE DOES NOT HOLD ANYTHING IN PLACE.
#
# docs/BUILD.md records the revision each vendored tree was audited and built against, and until now
# nothing compared that to the tree. A `git -C vendor/x checkout` or a re-clone moves one and the
# table keeps naming the old number — so "checked against upstream" quietly becomes "against
# whatever happens to be there", which is the same failure the fingerprint table had and the same
# reason it is now gated. Every tree the table gives a revision for has a .git, so this is a
# rev-parse; zlib names a release instead and bearssl has neither, and both are excluded by the
# pattern rather than by a list, since the pattern is what the table's own shape says.
#
# It also refuses an EMPTY reading. A gate that walks a table it can no longer find would report
# success for a docs/BUILD.md that lost the section, which is exactly the shape of check that is worse than
# no check at all.
# ⚠️ AND THE ROWS ARE READ ONCE. The count that refuses an empty reading used to be a SECOND sed,
# spelling the same row shape a second time — so narrowing the walk's pattern alone would leave the
# count answering thirteen while the walk checked nothing, and the gate would print "all 13 sit at
# the revision docs/BUILD.md records" having asked about none. That is the failure the count exists to
# prevent, reintroduced by the way it was written. One sed, and the count is of what was walked.
check-vendor:
	@rows=$$(sh tools/vendor/pins.sh | awk '$$2 != "-"') || exit 1; \
	n=$$(printf '%s' "$$rows" | grep -c .); \
	[ "$$n" -gt 0 ] \
	    || { echo "  FAIL  no pinned revisions found in docs/BUILD.md: the table this reads is gone"; exit 1; }; \
	bad=$$(printf '%s\n' "$$rows" \
	    | while read -r name rev; do \
	        [ -e "vendor/$$name/.git" ] \
	            || { echo "$$name: docs/BUILD.md records $$rev, but vendor/$$name has no .git to check"; continue; }; \
	        h=$$(git -C vendor/$$name rev-parse --short=$${#rev} HEAD 2>/dev/null); \
	        [ "$$h" = "$$rev" ] || echo "$$name: docs/BUILD.md records $$rev, the checkout is at $$h"; \
	      done); \
	[ -z "$$bad" ] && echo "  ok    all $$n vendored trees sit at the revision docs/BUILD.md records" \
	    || { echo "$$bad" | sed 's|^|  FAIL  |'; exit 1; }

# tools/vendor/fetch.sh is how anyone else gets vendor/, so it has to fetch what the table pins.
# check-vendor holds the checkouts to the table; this holds the script to it, both ways, so a pin
# moved in one place and not the other fails here rather than on somebody's fresh clone.
check-fetch:
	@sh tools/vendor/check-fetch.sh

# THIRD_PARTY_NOTICES.md is generated from the licences in vendor/; a pin that moves can change one.
check-notices:
	@sh tools/public/notices.sh | cmp -s - THIRD_PARTY_NOTICES.md \
	    && echo "  ok    THIRD_PARTY_NOTICES.md matches the licences of the pinned trees" \
	    || { echo "  FAIL  THIRD_PARTY_NOTICES.md is stale: tools/public/notices.sh > THIRD_PARTY_NOTICES.md"; exit 1; }

.PHONY: check-hysteria-fixtures
check-hysteria-fixtures:
	@$(PYTHON) -m unittest discover -s test/hystand -p 'test_*.py'

check-builds: check-hysteria-fixtures check-shell check-config check-qgo-reasons check-goverify check-goroots check-rules check-tune check-workers check-parrot check-quiet-lib check-counters check-pend check-request check-reality-version check-retry check-pool check-refs check-names check-cites check-divergences check-ack check-alerts check-crypto check-rsa check-fingerprint check-vendor check-fetch check-notices check-checkpoint-analysis
	@$(MAKE) -s BUILD=$(BUILD)/without-hysteria HYSTERIA=0 $(BUILD)/without-hysteria/lc-tunnel \
	    >/dev/null && echo "  ok    lc-tunnel builds without the hysteria2 plane" \
	    || { echo "  FAIL  lc-tunnel does not build without the hysteria2 plane"; exit 1; }
	@$(MAKE) -s BUILD=$(BUILD)/with-hysteria HYSTERIA=1 $(BUILD)/with-hysteria/lc-tunnel \
	    >/dev/null && echo "  ok    lc-tunnel builds with the hysteria2 plane" \
	    || { echo "  FAIL  lc-tunnel does not build with the hysteria2 plane"; exit 1; }
	@# A version stamp that does not follow the version is worse than none, because it is believed —
	@# and that is exactly what the first attempt did. Passing it as -D meant make saw no reason to
	@# rebuild anything, so a router reported the previous commit and reported it confidently. Two
	@# builds of the SAME tree with different versions is the only thing that catches it.
	@$(MAKE) -s BUILD=$(BUILD)/stamp LC_VERSION=first $(BUILD)/stamp/lc-tunnel >/dev/null
	@$(MAKE) -s BUILD=$(BUILD)/stamp LC_VERSION=second $(BUILD)/stamp/lc-tunnel >/dev/null
	@test "$$($(BUILD)/stamp/lc-tunnel --version)" = "second" \
	    && echo "  ok    the version stamp follows LC_VERSION without a clean build" \
	    || { echo "  FAIL  the version stamp is stale: says '$$($(BUILD)/stamp/lc-tunnel --version)', built as 'second'"; exit 1; }
	@# And the same question about the FLAGS, which make does not track at all: -MMD writes header
	@# dependencies and never a compiler option, so a tree built twice with different flags links the
	@# two halves together and says nothing. Two builds of one object at different optimisation, into
	@# a directory that is NOT cleaned between them: the object has to come out different, and it can
	@# only do that if the change of flags rebuilt it.
	@$(MAKE) -s BUILD=$(BUILD)/flags EXTRA_CFLAGS=-O0 $(BUILD)/flags/src/core/buf.o >/dev/null
	@cp $(BUILD)/flags/src/core/buf.o $(BUILD)/flags/buf-O0.bin
	@$(MAKE) -s BUILD=$(BUILD)/flags EXTRA_CFLAGS=-O2 $(BUILD)/flags/src/core/buf.o >/dev/null
	@cmp -s $(BUILD)/flags/buf-O0.bin $(BUILD)/flags/src/core/buf.o \
	    && { echo "  FAIL  a change of compiler flags rebuilds nothing"; exit 1; } \
	    || echo "  ok    a change of compiler flags rebuilds what it affects"
	@# The certificate decompressor against a server that really compresses. The client offers all
	@# three algorithms now, so which one is exercised here is OpenSSL's choice — the script reads it
	@# out of the server's own log and refuses anything outside the three. See test/certcomp/live.sh
	@# for why the check fails rather than skips when the server declines to compress.
	@$(MAKE) -s $(BUILD)/lc-probe >/dev/null
	@BUILD=$(BUILD) sh test/certcomp/live.sh

# Removes what was built, never what was fetched. dl/ holds the cross toolchain and anything else
# that took a download to get; wiping those on a `clean` is how a one-command tidy-up turns into an
# afternoon.
clean:
	rm -rf $(BUILD)

.PHONY: all check check-builds check-rules check-tune check-workers check-parrot check-arm64 clean quic

# BLAKE2b is checked against Go's implementation, which is what Hysteria runs.
$(BUILD)/gen/blake2b_vectors.h: tools/blake2b/main.go
	@mkdir -p $(dir $@)
	cd tools/blake2b && go run . > $(abspath $@)

# -lmbedcrypto for a primitive that computes nothing with it: src/core/blake2b.c wipes its state
# through lc_wipe, and that is mbedtls_platform_zeroize (src/core/wipe.h says at length why a plain
# memset is not enough). BLAKE2b's only caller hashes the obfuscation password, so the state this
# test links is the one place the argument for that guarantee actually bites.
# X25519 computed by this tree's own field arithmetic, against RFC 7748 and against the mbedTLS it
# replaced. The reference implementation is written out INSIDE the suite rather than reached through
# kex.c, because kex.c is the caller being changed and a differential test that runs the same code
# twice proves nothing — so -lmbedcrypto is here for the comparison, not for the thing under test.
$(BUILD)/test-x25519: test/x25519/test_x25519.c src/tls/x25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# THE SAME TWO SUITES AGAIN ON ref10, because the build host has a 128-bit product and so compiles the
# radix-2^51 field (src/tls/fe25519.h) — which is what arm64 and x86-64 run, and NOT what the MIPS
# routers run. Without these two the representation every mipsel binary ships with would only ever
# be compiled here, by check-device, and never executed. LC_FE_REF10 on every translation unit, so
# that the header agrees with itself.
$(BUILD)/test-x25519-ref10: test/x25519/test_x25519.c src/tls/x25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -DLC_FE_REF10 -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-ed25519-ref10: test/ed25519/test_ed25519.c src/tls/ed25519.c src/tls/fe25519.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -DLC_FE_REF10 -o $@ test/ed25519/test_ed25519.c src/tls/fe25519.c $(LC_LIBS)

$(BUILD)/test-kex: test/kex/test_kex.c src/tls/kex.c src/tls/x25519.c src/tls/fe25519.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-blake2b: test/blake2b/test_blake2b.c src/core/blake2b.c $(BUILD)/gen/blake2b_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# Salamander, against packets the vendored hysteria itself produced, and its salt against the stream
# Go's math/rand gives. src/quic/obfs.c is included by the suite rather than linked, so only its two
# dependencies are named here. -Itest/obfs for the frozen vector files beside it — frozen, and not
# generated by the build, because hysteria's module pulls forty dependencies and `check` has to keep
# running with --network none; the headers say how to regenerate them.
$(BUILD)/test-obfs: test/obfs/test_obfs.c test/obfs/reference_salamander.h test/obfs/reference_gorand.h \
                    src/quic/obfs.c src/quic/gorand.c src/core/blake2b.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Itest/obfs -o $@ test/obfs/test_obfs.c src/core/blake2b.c \
	    src/quic/gorand.c $(LC_LIBS)

# Our hand-written QPACK, checked against nghttp3's decoder. It links the vendored library, which the
# shipped client deliberately does not — the note here used to say that made it no part of `check`,
# while `check` had listed it as a prerequisite and run it for as long as anyone can remember. A
# comment that contradicts the rule three lines below it is worse than none: the next person to
# decide whether this test is cheap enough to keep believes it.
$(BUILD)/test-h3: test/h3/test_h3.c src/quic/h3.c src/quic/huffman.c src/quic/pad.c \
                  src/quic/prefix.c src/quic/varint.c src/core/rnd.c src/core/gomap.c $(NGHTTP3_OBJ) $(QUIC_GEN) \
                  $(BUILD)/gen/qpack_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ $(SOURCES)

# No vendored implementation to check against: upstream's parser is in a Go package marked internal,
# which nothing outside its module may import. The cross-check for this layer is the node itself.
$(BUILD)/test-hy: test/hy/test_hy.c src/quic/hy.c src/quic/pad.c src/quic/varint.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

# Vision had no test at all until its two end-of-padding commands turned out to have been the same
# command in this code from the beginning. There is no vendored parser to check against here
# either — Xray's lives in the same binary as its proxy — so this test is written against the
# format, and against the cases a working connection never produces.
# Includes vless.c rather than linking it: what this pins is the addons switch, which is static, and
# the property is about the bytes it writes rather than about the three functions the header exposes.
# Includes xudp.c for the same reason test-vless includes vless.c: what is pinned is the frame the
# writer produces, and the reader beside it, both static and both meaningless apart from the bytes.
$(BUILD)/test-xudp: test/xudp/test_xudp.c src/vless/xudp.c src/vless/xudp.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/xudp/test_xudp.c

$(BUILD)/test-vless: test/vless/test_vless.c src/vless/vless.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/vless/test_vless.c

$(BUILD)/test-vision: test/vision/test_vision.c test/vision/reference_read.h src/vless/vision.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# What the filter decides about the stream inside, which is a different question from how Vision
# frames it — and a quieter one: framing that is wrong corrupts a stream loudly, a direct-copy
# decision that is wrong hands raw bytes through where ciphertext was expected and errors nowhere.
$(BUILD)/test-vfilter: test/vfilter/test_vfilter.c src/vless/vision.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# Where the node's answer ends and the proxied stream begins. Reached on every connection of the
# REALITY plane; test/vless beside it covers only what this client SENDS.
$(BUILD)/test-vresp: test/vresp/test_vresp.c src/vless/vless.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# The proof that the peer holds the key in the certificate it sent — absent from the REALITY plane
# once, present now, and held by nothing until this suite.
$(BUILD)/test-certverify: test/certverify/test_certverify.c src/tls/certverify.c src/cert/cert.c \
                          src/tls/ed25519.c src/tls/fe25519.c src/tls/hkdf.c $(BUILD)/gen/certverify_vectors.h \
                          $(BUILD)/gen/mldsacv_vectors.h \
                          $(CHAIN_SRC) $(CHAIN_KECCAK)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(CHAIN_DEFS) -I$(BUILD)/gen -o $@ test/certverify/test_certverify.c \
	    src/tls/certverify.c src/cert/cert.c src/tls/ed25519.c src/tls/fe25519.c src/tls/hkdf.c \
	    $(CHAIN_SRC) $(CHAIN_KECCAK) $(LC_LIBS)

# The prefixed integers both header compressions use, and the refusal the header names: a
# continuation that never ends is a denial of service the far end buys for ten bytes.
$(BUILD)/test-prefix: test/prefix/test_prefix.c src/quic/prefix.c src/quic/huffman.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# The two spellings a REALITY credential arrives in. src/core/args.h states the hazard at the
# declaration — "a key half read is a key that authenticates nothing" — and nothing held it.
$(BUILD)/test-keys: test/keys/test_keys.c src/core/args.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# The table header and its cursor, on tables that are wrong. test/fphello checks the shipped table
# renders correctly; this checks what happens to one that stopped halfway down a flash write, where
# the cursor's deferred overrun would otherwise produce a hello made of zeros.
$(BUILD)/test-fpt: test/fpt/test_fpt.c src/fp/fpt.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES) $(LC_LIBS)

# ---- keeping the build honest ------------------------------------------------

# Test programs compile straight from source, so there is no object file for a generated dependency
# list to attach to. They are told about every header instead: a header change rebuilds all of them,
# which costs a few seconds and removes the possibility of a test that passes against code that is
# no longer there.
#
# The recipes that build them use $^, so those had to learn to leave headers out of the compiler's
# argument list — see SOURCES. A header handed to cc as a source file is compiled on its own, which
# is how a header that had always been included after <stdint.h> turned out never to have included
# it itself.
# This line once ended in a literal backslash-n where a line continuation was meant. make does not
# read that as anything: it took `\n` for a target name, so the last four tests were declared as
# prerequisites of a phantom and none of the five on that line — nor test-args, which was simply
# missing — were rebuilt when a header changed. What that looks like is a suite that passes against
# code the header no longer describes. TESTS is now derived from the one list of names above, so
# there is no second place for a test to be missing from.
$(TESTS): $(HEADERS)

# What the compiler recorded about which header belongs to which object. Included last, and quietly:
# on a clean tree there are none yet, and that is not an error.
#
# ONLY THIS TREE'S OWN OBJECT DIRECTORIES, not everything under $(BUILD). Every build nested inside it
# — $(BUILD)/with-hysteria, $(BUILD)/stamp, $(BUILD)/device-hy1 and the rest, each a sub-make with a
# BUILD of its own — reads its own .d files when it runs, and the objects this make writes land in
# three places and nowhere else (the object rules above: $(BUILD)/src, $(BUILD)/vendor,
# $(BUILD)/ngtcp2-obj, plus the bench objects at the top). `find $(BUILD)` read all of them: five
# thousand files from forty-four subdirectories on a working tree, 46 s of parsing per invocation of
# make, and `make check` invokes it five times — four of the seven minutes the gate took were this line.
-include $(wildcard $(BUILD)/*.d) \
         $(shell find $(BUILD)/src $(BUILD)/vendor $(BUILD)/ngtcp2-obj -name '*.d' 2>/dev/null)

# HPACK, checked against nghttp2 the way QPACK is checked against nghttp3.
#
# nghttp2 is compiled only for this test and linked into nothing that ships. Its version header is
# generated the same way the other two are.
NGHTTP2_SRC = $(wildcard $(NGHTTP2_DIR)/lib/*.c) $(wildcard $(NGHTTP2_DIR)/lib/sfparse/*.c)
NGHTTP2_OBJ = $(NGHTTP2_SRC:%.c=$(BUILD)/%.o)
NGHTTP2_INC = -I$(BUILD)/gen -I$(NGHTTP2_DIR)/lib -I$(NGHTTP2_DIR)/lib/includes

# Named nghttp2ver.h here rather than version.h, unlike the other two.
$(BUILD)/gen/nghttp2/nghttp2ver.h: $(NGHTTP2_DIR)/lib/includes/nghttp2/nghttp2ver.h.in
	@mkdir -p $(dir $@)
	sed -e 's/@PACKAGE_VERSION@/1.68.0/' -e 's/@PACKAGE_VERSION_NUM@/0x014400/' $< > $@

$(BUILD)/$(NGHTTP2_DIR)/%.o: $(NGHTTP2_DIR)/%.c $(BUILD)/gen/nghttp2/nghttp2ver.h $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(VENDOR_CFLAGS) $(NGHTTP2_INC) -c -o $@ $<

# What x/net's HPACK decoder makes of header blocks fed a piece at a time, malformed ones included —
# what lc_hpack_write and lc_hpack_close are held to. Builds from vendor/, no network. See
# tools/hpackdec/main.go.
# When Go's gzip reader reads its body, logged from Go's own reader over bodies that arrive in
# pieces — what core/gozip is held to. No network. See tools/gozip/main.go.
$(BUILD)/gen/gozip_vectors.h: tools/gozip/main.go
	@mkdir -p $(dir $@)
	cd tools/gozip && $(GO127) run . > $(abspath $@)

$(BUILD)/test-gozip: test/gozip/test_gozip.c src/core/gozip.c $(BUILD)/gen/gozip_vectors.h
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ test/gozip/test_gozip.c src/core/gozip.c $(LDFLAGS) $(LC_LIBS)

$(BUILD)/test-gozip-parallel: test/gozip/test_parallel.c src/core/gozip.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ $(SOURCES) $(LDFLAGS) $(LC_LIBS)

# The Hysteria2 authentication request's field section as qpack itself encodes it (vendor/qpack, the
# v0.6.0 quic-go requires): what lc_h3_auth_request_with is held to, byte for byte. No network. See
# tools/qpackvec/main.go.
$(BUILD)/gen/qpack_vectors.h: tools/qpackvec/main.go $(wildcard vendor/qpack/*.go)
	@mkdir -p $(dir $@)
	cd tools/qpackvec && go run . > $(abspath $@)

$(BUILD)/gen/hpackdec_vectors.h: tools/hpackdec/main.go
	@mkdir -p $(dir $@)
	cd tools/hpackdec && go run . > $(abspath $@)

$(BUILD)/test-hpack: test/hpack/test_hpack.c test/hpack/reference_enc.h $(BUILD)/gen/hpackdec_vectors.h src/h2/hpack.c src/quic/huffman.c src/quic/prefix.c \
                     $(BUILD)/gen/hpack_static.h $(BUILD)/gen/nghttp2/nghttp2ver.h $(NGHTTP2_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(NGHTTP2_INC) -o $@ $(SOURCES)

$(BUILD)/test-h2frame: test/h2/test_frame.c src/h2/frame.c \
                       $(BUILD)/gen/nghttp2/nghttp2ver.h $(NGHTTP2_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(NGHTTP2_INC) -o $@ $(SOURCES)

# browser.c because the request now carries the Chrome identity the reference puts on every XHTTP
# request — see the note in src/h2/xhttp.c. The test links it rather than stubbing it: what the
# header block contains is the whole of what this test is for.
$(BUILD)/test-xhttp: test/h2/test_xhttp.c src/h2/xhttp.c src/h2/frame.c src/h2/hpack.c \
                     src/quic/huffman.c src/quic/prefix.c src/quic/pad.c src/core/rnd.c src/core/gomap.c \
                     src/reality/browser.c src/quic/gorand.c \
                     $(BUILD)/gen/hpack_static.h $(BUILD)/gen/nghttp2/nghttp2ver.h $(NGHTTP2_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(NGHTTP2_INC) -o $@ $(SOURCES)

XFETCH_SRC = src/cmd/lc-xfetch/main.c
XFETCH_OBJ = $(XFETCH_SRC:%.c=$(BUILD)/%.o)


$(BUILD)/src/h2/%.o: src/h2/%.c $(BUILD)/gen/hpack_static.h $(LC_FLAGS_STAMP)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -I$(BUILD)/gen -c -o $@ $<

$(BUILD)/lc-xfetch: $(XFETCH_OBJ) $(H2_OBJ) $(LIB_OBJ) $(MLKEM_OBJ) $(SPIDER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LC_LIBS)

$(BUILD)/test-events: test/loop/test_events.c src/net/loop.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

# One listener shared by workers, each waiting with LC_EV_EXCLUSIVE: a connection goes to a worker
# that is idle and wakes nobody else — the rule lc-tunnel's REALITY workers accept by.
$(BUILD)/test-share: test/loop/test_share.c src/net/loop.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

# The reader thread's teardown, against a reader that is kept busy with clients closing their end:
# every stage is unmapped the moment it is removed, so a reader that looks at one afterwards faults.
$(BUILD)/test-reader: test/reader/test_reader.c src/net/reader.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

# The send queue's writer thread through its public interface, on sockets whose fullness the suite
# controls: ordering, the eight-waiting boundary, the owner's wake, and a close that has to end.
# The node's packets opened ahead on other threads, and the callbacks that answer from them: every
# answer against the one the callback computes itself — see test/rxopen/test_rxopen.c.
$(BUILD)/test-rawin: test/rawin/test_rawin.c test/rawin/reference.h src/tls/rawin.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -Itest/rawin -o $@ test/rawin/test_rawin.c src/tls/rawin.c

# Go's resolver as src/net/goresolve.c transcribes it, the parts that need no network — the resolver
# itself, queries and all, is held to Go's by tools/vendorcap/dnsstand. goresolve.c arrives through
# the #include.
$(BUILD)/test-goresolve: test/goresolve/test_goresolve.c src/net/goresolve.c src/net/goresolve.h \
                         src/core/netip.c src/core/goquote.c src/core/rnd.c
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ test/goresolve/test_goresolve.c src/core/netip.c \
	    src/core/goquote.c src/core/rnd.c

$(BUILD)/test-recopen: test/recopen/test_recopen.c src/tls/recopen.c src/tls/record.c src/core/rnd.c src/tls/aead.c $(GHASH_SRC) $(CHACHA_SRC)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -pthread -o $@ $(SOURCES) $(LC_LIBS)

$(BUILD)/test-rxopen: test/rxopen/test_rxopen.c $(QUIC_OBJ) $(NGTCP2_OBJ) $(NGHTTP3_OBJ) $(LIB_OBJ) \
                      $(MLKEM_OBJ) $(QUIC_GEN)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) $(QUIC_INC) -o $@ $(SOURCES) $(LC_LIBS) \
	    -Wl,--wrap=sysconf,--wrap=pthread_cond_signal,--wrap=pthread_cond_broadcast,--wrap=pthread_create,--wrap=pthread_join

$(BUILD)/test-sendq: test/sendq/test_sendq.c src/quic/sendq.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ $(SOURCES)

$(BUILD)/test-sendq-poll: test/sendq/test_poll.c src/quic/sendq.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(TEST_CFLAGS) -o $@ test/sendq/test_poll.c
