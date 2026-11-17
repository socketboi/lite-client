/* lc-hello — build a ClientHello from a packed fingerprint table and write it out.
 *
 * This is not part of the client; it is what lets the client's most delicate piece be tested from
 * the outside. The output goes straight into `fp diff`, which compares it against uTLS, so the
 * builder is accepted by measurement rather than by inspection. */

#include "core/args.h"
#include "fp/hello.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A hello never approaches this: the largest fingerprint measured is under 2 KB, and the record
 * layer caps a handshake message at 16 KB anyway. Sized once, on the stack, so the tool allocates
 * nothing at all. */
#define MAX_HELLO 16384
#define MAX_TABLE 65536

static const char *err_text(lc_hello_err e)
{
    switch (e) {
    case LC_HELLO_OK:        return "ok";
    case LC_HELLO_BAD_TABLE: return "table does not parse, or declares a mode this build cannot honour";
    case LC_HELLO_NO_SPACE:  return "output buffer too small";
    case LC_HELLO_NO_RANDOM: return "system refused to provide randomness";
    case LC_HELLO_BAD_SNI:   return "server name does not fit the wire encoding";
    }
    return "unknown";
}

/* lc_read_file with a message, rather than a second copy of it. The copy that stood here carried the
 * same off-by-one at the boundary — a file of exactly `cap` bytes refused as too big — and would
 * have gone on carrying it, because nothing links the two. */
static long read_file(const char *path, uint8_t *dst, size_t cap)
{
    long n = lc_read_file(path, dst, cap);
    if (n < 0)
        fprintf(stderr, "cannot read %s, or it is larger than %zu bytes\n", path, cap);
    return n;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: lc-hello TABLE.fpt SNI OUT.bin\n");
        return LC_EXIT_CONFIG;
    }

    static uint8_t table[MAX_TABLE];
    long           table_len = read_file(argv[1], table, sizeof table);
    if (table_len < 0)
        return LC_EXIT_CONFIG;

    static uint8_t hello[MAX_HELLO];
    lc_hello_out   info;

    lc_hello_err err = lc_hello_build(table, (size_t)table_len, argv[2],
                                      hello, sizeof hello, &info);
    if (err != LC_HELLO_OK) {
        fprintf(stderr, "build failed: %s\n", err_text(err));
        return LC_EXIT_CONFIG;
    }

    FILE *out = fopen(argv[3], "wb");
    if (out == NULL) {
        /* A path that cannot be written is the command line being wrong, not the network. Retrying
         * gets the same answer, and 1 is the code that tells a script to retry. */
        fprintf(stderr, "cannot write %s\n", argv[3]);
        return LC_EXIT_CONFIG;
    }
    size_t written = fwrite(hello, 1, info.len, out);
    if (fclose(out) != 0 || written != info.len) {
        fprintf(stderr, "short write to %s\n", argv[3]);
        return LC_EXIT_CONFIG;
    }

    printf("%zu bytes, session_id at offset %zu, %u key slots -> %s\n",
           info.len, info.sid_off, info.slot_count, argv[3]);
    for (unsigned i = 0; i < info.slot_count; i++)
        printf("  key_share group 0x%04x: %zu bytes at offset %zu\n",
               info.slots[i].group, info.slots[i].len, info.slots[i].off);
    return LC_EXIT_OK;
}
