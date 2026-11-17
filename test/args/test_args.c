/* What a command line is allowed to mean.
 *
 * These arguments are not user input in the usual sense — nobody types them, an init script does —
 * which is exactly why getting them wrong is quiet. A tool that starts, prints that it is listening,
 * and listens on the wrong port has reported success; the connection that was meant to arrive simply
 * never does, and every minute of the search that follows is spent on the tunnel.
 *
 * That is not hypothetical: `lc-tunnel ... 127.0.0.1:11081 ...` was run against a live node, atoi
 * read 127 out of it, the tool bound port 127 and said "listening on 127". The argument was wrong —
 * LISTEN takes a bare port — and nothing in the program was willing to say so.
 *
 * So the cases here are the ones atoi answers rather than refuses. */

#include "core/args.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

static void expect(int cond, const char *what)
{
    if (cond) {
        printf("  ok    %s\n", what);
        return;
    }
    printf("  FAIL  %s\n", what);
    failures++;
}

/* Refused, AND the caller's variable left alone: a tool that ignores the return value must not find
 * a plausible number waiting for it. */
static int refused(const char *s)
{
    uint16_t port = 0xbeefu;
    return lc_port(s, &port) != 0 && port == 0xbeefu;
}

static int accepts(const char *s, uint16_t want)
{
    uint16_t port = 0;
    return lc_port(s, &port) == 0 && port == want;
}

/* The receive rate the Hysteria2 tools state to the node, which strtoull used to read. Its failures
 * are the same shape as atoi's and one step worse: a rate of zero is not a slow node, it is Brutal
 * switched off, so the tool measured ordinary congestion control and reported the figure as this
 * protocol's. */
static int rate_refused(const char *s)
{
    uint64_t rate = 0xbeefu;
    return lc_u64(s, &rate) != 0 && rate == 0xbeefu;
}

static int rate_accepts(const char *s, uint64_t want)
{
    uint64_t rate = 0;
    return lc_u64(s, &rate) == 0 && rate == want;
}

/* A target as every tool takes it, into the two things a connection needs. */
static int hp_accepts(const char *spec, uint16_t def, const char *want_host, uint16_t want_port)
{
    char     host[64] = { 0 };
    uint16_t port = 0;
    return lc_host_port(spec, host, sizeof host, &port, def) == 0 &&
           strcmp(host, want_host) == 0 && port == want_port;
}

static int hp_refused(const char *spec)
{
    char     host[64] = "untouched";
    uint16_t port = 0xbeefu;
    return lc_host_port(spec, host, sizeof host, &port, 80u) != 0 &&
           strcmp(host, "untouched") == 0 && port == 0xbeefu;
}

/* A file holding exactly these bytes, NUL included — fputs cannot write one, and a NUL in the file
 * is the case worth asking about. */
static const char *secret_bytes(const void *content, size_t len, mode_t mode)
{
    static char path[64], arg[80];
    snprintf(path, sizeof path, "/tmp/lc-secret-raw-%d", (int)getpid());
    unlink(path);

    FILE *f = fopen(path, "wb");
    if (f == NULL)
        return "@/nonexistent";
    if (len > 0 && fwrite(content, 1, len, f) != len) {
        fclose(f);
        return "@/nonexistent";
    }
    fclose(f);
    if (chmod(path, mode) != 0)
        return "@/nonexistent";

    snprintf(arg, sizeof arg, "@%s", path);
    return arg;
}

/* A file holding a secret, written the way a deployment is told to write one, and named the way a
 * command line names it: with a leading @. */
static const char *secret_arg(const char *content, mode_t mode)
{
    static char path[64], arg[80];
    snprintf(path, sizeof path, "/tmp/lc-secret-%d", (int)getpid());
    unlink(path);

    FILE *f = fopen(path, "w");
    if (f == NULL)
        return "@/nonexistent";
    fputs(content, f);
    fclose(f);
    if (chmod(path, mode) != 0)
        return "@/nonexistent";

    snprintf(arg, sizeof arg, "@%s", path);
    return arg;
}

/* A symbolic link where the file is meant to be — the shape of the attack the checks exist for:
 * whoever can create it chooses which file's first line the node is told is our password. */
static const char *secret_link(void)
{
    static char path[64], arg[80];
    const char *target = secret_arg("hunter2\n", 0600) + 1;

    snprintf(path, sizeof path, "/tmp/lc-secret-link-%d", (int)getpid());
    unlink(path);
    if (symlink(target, path) != 0)
        return "@/nonexistent";

    snprintf(arg, sizeof arg, "@%s", path);
    return arg;
}

static int reads_secret(const char *arg, const char *want)
{
    char out[128] = { 0 };
    return lc_read_secret(arg, out, sizeof out) == LC_SECRET_OK && strcmp(out, want) == 0;
}

static int secret_refused(const char *arg, int why)
{
    char out[128] = { 0 };
    return lc_read_secret(arg, out, sizeof out) == why;
}

int main(void)
{
    printf("\nwhat a command line is allowed to mean\n\n");

    expect(accepts("443", 443u), "a port is a port");
    expect(accepts("1", 1u), "and so is the lowest one");
    expect(accepts("65535", 65535u), "and the highest");
    expect(accepts("00443", 443u), "leading zeros are digits, not an error");

    expect(refused("127.0.0.1:11081"), "a host:port where a port was wanted is refused, not read as 127");
    expect(refused("443/tcp"), "and so is a port with anything after it");
    expect(refused(" 443"), "or before it");
    expect(refused("443 "), "or a trailing space, which a shell script splits in");

    expect(refused("0"), "zero is refused: bind would pick one at random and report success");
    expect(refused("-1"), "a negative number is refused rather than wrapped to 65535");
    expect(refused("65536"), "one past the top is refused");
    expect(refused("4294967739"), "and so is a value that wraps to a legal port in 32 bits");
    expect(refused("99999999999999999999"), "a number too large for any integer is refused, not folded");

    expect(refused(""), "an empty argument is not a port");
    expect(refused(NULL), "and neither is a missing one");

    expect(rate_accepts("12500000", 12500000u), "a rate in bytes per second is a rate");
    expect(rate_accepts("0", 0u), "and zero is one of them: it means the node decides");
    expect(rate_refused("100mbps"), "the spelling hysteria's config uses is refused, not read as 100");
    expect(rate_refused("abc"), "a word is refused rather than read as no rate at all");
    expect(rate_refused("-1"), "a negative rate is refused rather than wrapped to the top of the range");
    expect(rate_refused("18446744073709551616"), "one past what fits is refused, not folded to zero");
    expect(rate_accepts("18446744073709551615", 18446744073709551615u), "and the largest that fits is kept whole");

    uint16_t qtype = 0xbeefu;
    expect(lc_u16("28", &qtype) == 0 && qtype == 28u, "a DNS query type is a sixteen-bit number");
    expect(lc_u16("0", &qtype) == 0 && qtype == 0u, "zero is a value here, unlike a port");
    qtype = 0xbeefu;
    expect(lc_u16("AAAA", &qtype) != 0 && qtype == 0xbeefu, "a type spelled by name is refused, not read as type 0");
    expect(lc_u16("-1", &qtype) != 0 && qtype == 0xbeefu, "and a negative one is refused rather than wrapped to 65535");
    expect(lc_u16("65536", &qtype) != 0 && qtype == 0xbeefu, "one past the top is refused");

    /* A target, which every tool takes and each of them used to split for itself. */
    printf("\nand what a target is allowed to mean\n\n");

    expect(hp_accepts("example.com", 80u, "example.com", 80u), "a bare name takes the default port");
    expect(hp_accepts("example.com:443", 80u, "example.com", 443u), "and a written one wins over it");
    expect(hp_accepts("192.0.2.1:53", 80u, "192.0.2.1", 53u), "an address is a host like any other");
    expect(hp_accepts("[2001:db8::1]:443", 80u, "2001:db8::1", 443u),
           "an IPv6 literal in brackets keeps its colons");
    expect(hp_accepts("[2001:db8::1]", 53u, "2001:db8::1", 53u), "with or without a port after it");

    expect(hp_refused("example.com:htp"), "a port that is not a number is refused, not passed on");
    expect(hp_refused("example.com:"), "and neither is an empty one a port");
    expect(hp_refused("example.com:0"), "nor zero, which no connection can be made to");
    expect(hp_refused("example.com:65536"), "nor one past the top");
    expect(hp_refused(":443"), "a spec with no host at all is refused");
    expect(hp_refused("2001:db8::1"), "an unbracketed IPv6 literal is refused rather than cut short");
    expect(hp_refused("[2001:db8::1]x"), "and so is a bracket with rubbish after it");
    expect(hp_refused("[]:443"), "or brackets with nothing in them");
    {
        char     host[8];
        uint16_t port = 0;
        expect(lc_host_port("a-very-long-name.example:443", host, sizeof host, &port, 80u) != 0,
               "a host too long for the caller's buffer is refused, not truncated");
    }
    {
        char     host[64];
        uint16_t port = 0;
        expect(lc_host_port("example.com", host, sizeof host, &port, 0u) != 0,
               "and where the caller says a port must be written, a bare name is not a target");
    }

    /* Secrets, whose two forms have to mean the same thing. */
    printf("\nand what a secret is allowed to be\n\n");

    expect(reads_secret("hunter2", "hunter2"), "a literal secret is the secret");
    expect(secret_refused("", LC_SECRET_EMPTY),
           "an empty literal is not a password, any more than an empty file is");

    expect(reads_secret(secret_arg("hunter2\n", 0600), "hunter2"),
           "a file holding it says the same thing");
    expect(reads_secret(secret_arg("hunter2", 0600), "hunter2"),
           "with or without the newline an editor puts there");
    expect(reads_secret(secret_arg("hunter2\r\n", 0600), "hunter2"),
           "and a file written on Windows is the same file");
    expect(reads_secret(secret_arg("hunter2\nnotes below\n", 0600), "hunter2"),
           "the first line is the secret; what follows it is somebody's note");

    /* The boundary the two forms disagreed on. 127 characters is what a 128-byte buffer holds, and
     * fgets stops one short of the buffer without taking the newline with it — so the longest secret
     * that fits was read whole from a file and then refused for not having ended. */
    {
        char longest[128];
        memset(longest, 'a', sizeof longest - 1);
        longest[sizeof longest - 1] = '\0';

        char with_nl[130];
        snprintf(with_nl, sizeof with_nl, "%s\n", longest);
        expect(reads_secret(secret_arg(with_nl, 0600), longest),
               "the longest secret that fits is read from a file, not refused for its length");
        expect(reads_secret(longest, longest), "as it is on the command line");

        char over[130];
        snprintf(over, sizeof over, "%sb\n", longest);
        expect(secret_refused(secret_arg(over, 0600), LC_SECRET_TOO_LONG),
               "one character more is refused rather than cut down to fit");
    }

    /* A ZERO BYTE IN THE FILE, which read as a short and perfectly valid secret.
     *
     * The guard against a truncated secret was built on strlen, and strlen stops at the first NUL:
     * "pa\0ssword\n" measured two characters, ended on a newline, and came back OK holding "pa".
     * The node then answers a wrong secret the way it answers any stranger — with the web page it
     * pretends to be — so the symptom is a tunnel that connects and carries nothing, and no line
     * anywhere saying the secret was cut. A file saved as UTF-16 reaches this on its second byte. */
    expect(secret_refused(secret_bytes("pa\0ssword\n", 10, 0600), LC_SECRET_HAS_NUL),
           "a zero byte inside the secret is refused, not silently taken as its first half");
    expect(secret_refused(secret_bytes("hunter2\0", 8, 0600), LC_SECRET_HAS_NUL),
           "and a file ending in one is refused too, terminator or not");

    expect(secret_refused(secret_arg("", 0600), LC_SECRET_EMPTY),
           "an empty file is nothing to authenticate with, and says so");
    /* lc_read_file, whose header says "-1 if it does not fit in cap" and which refused a file that
     * fitted exactly. feof was false because fread had satisfied the request without reaching the
     * end, so the one boundary the function makes a promise about was the one it got wrong. Nothing
     * in the tree reaches it today — the fingerprint tables are kilobytes and the cap is 64K — which
     * is exactly why it was worth asking rather than assuming. */
    {
        uint8_t     into[8];
        const char *eight = secret_bytes("12345678", 8, 0600) + 1; /* past the @ */
        expect(lc_read_file(eight, into, sizeof into) == 8,
               "a file of exactly the size offered fits, and is read whole");
        expect(lc_read_file(eight, into, sizeof into - 1u) == -1,
               "and one byte more than the room offered does not");
        const char *seven = secret_bytes("1234567", 7, 0600) + 1;
        expect(lc_read_file(seven, into, sizeof into) == 7, "a shorter one is read and measured");
        expect(lc_read_file(seven, NULL, 0) == -1, "nonempty input does not fit a zero-byte buffer");
        const char *empty = secret_bytes("", 0, 0600) + 1;
        expect(lc_read_file(empty, NULL, 0) == 0, "empty regular input fits a zero-byte buffer");
        expect(lc_read_file("/dev/zero", into, sizeof into) == -1,
               "a character device is refused without reading a prefix");
        expect(lc_read_file("/tmp", into, sizeof into) == -1, "a directory is not a public input file");
    }

    expect(secret_refused("@/nonexistent/lite-client/auth", LC_SECRET_NO_FILE),
           "a file that is not there says that, rather than sending the reader to check modes");
    expect(secret_refused(secret_arg("hunter2\n", 0644), LC_SECRET_OPEN_TO_OTHERS),
           "a secret every process on the box can read is refused, and named as a mode problem");
    expect(secret_refused("@/dev/zero", LC_SECRET_NOT_REGULAR),
           "and something that is not a file at all is refused before it is read");
    expect(secret_refused(secret_link(), LC_SECRET_NO_FILE),
           "a symbolic link left where the file should be is not followed");

    printf("\n%s\n", failures == 0 ? "an argument that is not a number cannot become one"
                                   : "an argument that is not a number became one");
    return failures == 0 ? 0 : 1;
}
