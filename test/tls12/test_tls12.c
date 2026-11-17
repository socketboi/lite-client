/* TLS 1.2 (T3): what the build cannot be caught out on.
 *
 * tls/suite.h leaves out uTLS's 3DES and RC4 suites on one condition — that no hello this client
 * sends offers them, so that no server can pick one. That condition is a property of the shipped
 * fingerprint tables, not of the code, and a table is data: this reads every one that ships, builds
 * the hello it makes, and refuses a suite in it that uTLS would run and this build would not. The
 * handshake itself is test/tls12/run.sh's, against Go's own server. */

#include "fp/hello.h"
#include "tls/suite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void expect(int cond, const char *what)
{
    printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
    if (!cond)
        failures++;
}

static void table(const char *path)
{
    static uint8_t buf[65536], hello[4096];
    FILE          *f = fopen(path, "rb");
    if (f == NULL) {
        printf("  FAIL  cannot open %s\n", path);
        failures++;
        return;
    }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);

    lc_hello_out info;
    if (lc_hello_build(buf, n, "tls12.test", hello, sizeof hello, &info) != LC_HELLO_OK) {
        printf("  FAIL  %s does not build a hello\n", path);
        failures++;
        return;
    }
    /* The cipher_suites vector: past the header, the version, the random and the session id. */
    size_t off = 4u + 2u + 32u;
    off += 1u + hello[off];
    size_t len = (size_t)hello[off] << 8 | hello[off + 1u];
    off += 2u;
    unsigned tls12 = 0, missing = 0;
    for (size_t i = 0; i + 1u < len; i += 2u) {
        uint16_t id = (uint16_t)((uint16_t)hello[off + i] << 8 | hello[off + i + 1u]);
        if ((id & 0xff00u) == 0x1300u || ((id >> 8) == (id & 0xffu) && (id & 0xfu) == 0xau))
            continue; /* TLS 1.3's, and GREASE */
        if (lc_tls12_suite_known_to_go(id)) {
            tls12++;
            if (lc_tls12_suite_by_id(id) == NULL) {
                printf("        0x%04x is uTLS's and not this build's\n", id);
                missing++;
            }
        }
    }
    char what[256];
    snprintf(what, sizeof what, "%s: all %u TLS 1.2 suites uTLS would run are this build's too", path,
             tls12);
    expect(tls12 > 0u && missing == 0u, what);
}

int main(void)
{
    printf("TLS 1.2: no shipped hello offers a suite this build cannot run\n");
    table("package/files/fingerprint.fpt");
    table("test/fphello/chrome.fpt");
    if (failures) {
        printf("%d FAILED\n", failures);
        return 1;
    }
    printf("all good\n");
    return 0;
}
