#!/bin/sh
# Link stubs for the two cross builds, made the way docs/BUILD.md describes ("Cross-compiling for the
# router" and the aarch64 section after it), for a machine that starts with nothing in dl/.
#
# Run inside lc-build:local from the root of the tree, after `make tc-fetch`:
#
#   sh .github/scripts/link-stubs.sh
#
# The OpenWrt toolchain has no mbedTLS or zlib to link against, and the libraries on a device are
# stripped of section headers, so ld is given empty libraries that carry the right names and the
# right sonames. The names come from the objects themselves: both planes are compiled for mipsel
# (the link fails, since there are no stubs yet, and -k keeps make compiling so that every object
# exists), and whatever they leave undefined under mbedTLS's and zlib's prefixes becomes a stub.
# The set does not depend on the architecture, so aarch64 gets the same stubs built with its own
# compiler.
#
# A source file that does not compile leaves its names out of the stub. That is not hidden: the gate
# then fails in check-device on the compile error itself.
#
# MIPSLIB, A64LIB and OBJDIR can be pointed elsewhere to try this without touching dl/.
set -eu

MIPSLIB=${MIPSLIB:-dl/mipslib}
A64LIB=${A64LIB:-dl/a64lib}
OBJDIR=${OBJDIR:-build/stubs}

# The toolchain directory that contains the named compiler (see CROSS_TC in the Makefile for why it
# is found by the binary and not by the directory name).
toolchain() {
	for d in "$1"/*/toolchain-*/; do
		[ -x "$d/bin/$2" ] && { echo "${d%/}"; return 0; }
	done
	echo "no $2 under $1: run \`make tc-fetch\` first" >&2
	return 1
}

MIPS=$(toolchain dl/tc mipsel-openwrt-linux-gcc)
A64=$(toolchain dl/tc-a64 aarch64-openwrt-linux-gcc)
export STAGING_DIR="$PWD/$MIPS"
PATH="$PWD/$MIPS/bin:$PWD/$A64/bin:$PATH"

# The logs sit next to the object trees, and on a fresh checkout nothing has made that directory yet:
# a redirection into a missing directory fails before make runs, and `|| true` would hide it.
mkdir -p "$MIPSLIB" "$A64LIB" "$(dirname "$OBJDIR")"
for hy in 0 1; do
	make -k -s BUILD="$OBJDIR-hy$hy" HYSTERIA=$hy CC=mipsel-openwrt-linux-gcc \
		MBEDTLS_INC=vendor/mbedtls/include ZLIB_INC=vendor/zlib MBEDTLS_LIB="$MIPSLIB" all \
		>"$OBJDIR-hy$hy.log" 2>&1 || true
done

undef=$(find "$OBJDIR-hy0" "$OBJDIR-hy1" -name '*.o' -exec mipsel-openwrt-linux-nm -u {} + \
	| awk 'NF == 2 && $1 == "U" {print $2}' | sort -u)
[ -n "$undef" ] || { echo "no objects were compiled; see $OBJDIR-hy0.log" >&2; exit 1; }

stub() { sed 's/.*/void &(void) {}/'; }
printf '%s\n' "$undef" | grep '^mbedtls_' | grep -v '^mbedtls_x509_' | stub > "$MIPSLIB/stub.c"
printf '%s\n' "$undef" | grep '^mbedtls_x509_' | stub > "$MIPSLIB/stubx509.c"
printf '%s\n' "$undef" | grep -E '^(uncompress|compress|inflate|deflate|crc32|adler32|zlibVersion)' \
	| stub > "$MIPSLIB/stubz.c"
cp "$MIPSLIB/stub.c" "$MIPSLIB/stubx509.c" "$MIPSLIB/stubz.c" "$A64LIB/"

# The file is what -l finds; the soname is what the binary records and the device resolves.
for pair in mipsel:"$MIPSLIB" aarch64:"$A64LIB"; do
	cc=${pair%%:*}-openwrt-linux-gcc
	dir=${pair#*:}
	[ "$cc" = aarch64-openwrt-linux-gcc ] && export STAGING_DIR="$PWD/$A64"
	$cc -shared -fPIC -nostdlib -Wl,-soname,libmbedcrypto.so.16 -o "$dir/libmbedcrypto.so" "$dir/stub.c"
	$cc -shared -fPIC -nostdlib -Wl,-soname,libmbedx509.so.7 -o "$dir/libmbedx509.so" "$dir/stubx509.c"
	$cc -shared -fPIC -nostdlib -Wl,-soname,libz.so.1 -o "$dir/libz.so" "$dir/stubz.c"
done

echo "stubs: $(wc -l < "$MIPSLIB/stub.c") mbedcrypto, $(wc -l < "$MIPSLIB/stubx509.c") x509, $(wc -l < "$MIPSLIB/stubz.c") zlib names"
