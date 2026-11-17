#include "core/args.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int lc_from_hex(const char *s, uint8_t *out, size_t out_len)
{
    if (strlen(s) != out_len * 2u)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi = nibble(s[i * 2]), lo = nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

int lc_u64(const char *s, uint64_t *out)
{
    if (s == NULL || *s == '\0')
        return -1;

    /* Bounded before the multiply rather than after it, so a string of thirty digits is refused
     * rather than folded into whatever is left of it — a receive rate that wrapped would be a
     * plausible-looking number the node then obeys. */
    uint64_t v = 0;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        unsigned d = (unsigned)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u)
            return -1;
        v = v * 10u + d;
    }

    *out = v;
    return 0;
}

int lc_u16(const char *s, uint16_t *out)
{
    uint64_t v;
    if (lc_u64(s, &v) != 0 || v > 65535u)
        return -1;
    *out = (uint16_t)v;
    return 0;
}

int lc_port(const char *s, uint16_t *out)
{
    /* A port is the sixteen-bit case with one value taken out of it. Written on top of the general
     * parser rather than beside it: the two carried the same digit loop, and a copy of a loop is a
     * copy that stops agreeing — the one here bounded at 65535 while the other bounded at the top of
     * its own type, and only one of them would have been fixed. */
    uint16_t v;
    if (lc_u16(s, &v) != 0)
        return -1;
    if (v == 0)
        return -1; /* bind would pick one at random, which is never what a command line meant */

    *out = v;
    return 0;
}

int lc_from_base64url(const char *s, uint8_t *out, size_t out_len)
{
    static const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t   bits = 0, written = 0;
    uint32_t acc = 0;
    for (const char *p = s; *p != '\0'; p++) {
        const char *at = strchr(alphabet, *p);
        if (at == NULL)
            return -1;
        acc = acc << 6 | (uint32_t)(at - alphabet);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (written >= out_len)
                return -1;
            out[written++] = (uint8_t)(acc >> bits);
        }
    }
    return written == out_len ? 0 : -1;
}

long lc_read_file(const char *path, uint8_t *dst, size_t cap)
{
    /* Public input files may be symlinks, but must resolve to regular files.
     * Open nonblocking so a FIFO cannot stall startup before fstat rejects it. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    FILE *f = fdopen(fd, "rb");
    if (f == NULL) {
        close(fd);
        return -1;
    }
    size_t n = cap != 0u ? fread(dst, 1, cap, f) : 0u;
    /* Asked by reading one more, not by feof. A file of exactly `cap` bytes satisfies the request
     * without reaching the end, so feof was false and a file that fits exactly was refused as too
     * big — the one boundary this function makes a promise about. */
    int over = n == cap && fgetc(f) != EOF;
    int failed = ferror(f);
    if (fclose(f) != 0)
        failed = 1;
    return over || failed ? -1 : (long)n;
}

int lc_read_secret(const char *arg, char *out, size_t cap)
{
    if (arg[0] != '@') {
        if (strlen(arg) >= cap)
            return LC_SECRET_TOO_LONG;
        snprintf(out, cap, "%s", arg);
        /* Refused in this form as well as in the other one. An empty literal used to be a password:
         * `option auth ''` in a config file — which is what the file ships with — became an account
         * of no characters, offered to the node, refused there, and reported as a node that does not
         * want us rather than as a credential nobody set. */
        return out[0] == '\0' ? LC_SECRET_EMPTY : LC_SECRET_OK;
    }

    /* O_NOFOLLOW, and a regular file with nothing readable by anyone else.
     *
     * fopen would follow a symbolic link left in place of the file and read the first line of
     * whatever it points at — which is then sent to the node as the password. The three checks are
     * what the configuration file already claims ("Mode 0600, owned by root") and never verified. */
    /* Inspect non-regular inputs without blocking on a FIFO before fstat can reject it. */
    int fd = open(arg + 1, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return LC_SECRET_NO_FILE;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return LC_SECRET_NO_FILE;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return LC_SECRET_NOT_REGULAR;
    }
    if (st.st_uid != geteuid()) {
        close(fd);
        return LC_SECRET_NOT_OURS;
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(fd);
        return LC_SECRET_OPEN_TO_OTHERS;
    }

    FILE *f = fdopen(fd, "r");
    if (f == NULL) {
        close(fd);
        return LC_SECRET_NO_FILE;
    }
    /* Read a character at a time rather than with fgets, and the reason is NUL.
     *
     * A line that filled the buffer without ending is a secret longer than this holds. Taking its
     * first hundred and twenty-seven characters is the worst failure available: a node answers a
     * wrong secret with whatever it masquerades as, so the symptom is a web page where an answer
     * should be, and nothing anywhere says the secret was cut.
     *
     * "Without ending" has to include the case where the end is the next character, which it did
     * not: fgets stops one short of the buffer and leaves the newline in the file, so a secret of
     * exactly cap-1 characters was read whole and then refused for being too long — while the same
     * secret written on the command line was accepted. The two forms have to take the same secrets,
     * or moving one into a file is a change of meaning.
     *
     * And that guard was built on strlen, which stops at the first NUL — so a file holding
     * "pa\0ssword\n" measured two characters, ended cleanly, and returned OK with the secret cut to
     * "pa". Precisely the failure the paragraph above calls the worst available, arriving through
     * the gap between "how long the line is" and "how many bytes were read". A file saved as UTF-16
     * gets there on its second byte. fgets cannot report it at all, so the loop does the reading. */
    size_t n = 0;
    int    ended = 0;
    for (;;) {
        int c = fgetc(f);
        if (c == EOF || c == '\n' || c == '\r') {
            ended = 1;
            break;
        }
        if (c == '\0') {
            fclose(f);
            return LC_SECRET_HAS_NUL;
        }
        if (n + 1 >= cap)
            break;
        out[n++] = (char)c;
    }
    out[n] = '\0';
    fclose(f);

    if (!ended)
        return LC_SECRET_TOO_LONG;

    return n == 0 ? LC_SECRET_EMPTY : LC_SECRET_OK;
}

const char *lc_secret_why(int rc)
{
    switch (rc) {
    case LC_SECRET_OK:
        return "read";
    case LC_SECRET_TOO_LONG:
        return "it is longer than this holds, and half a secret is a wrong secret";
    case LC_SECRET_HAS_NUL:
        return "there is a zero byte in it; check the file is not utf-16";
    case LC_SECRET_NO_FILE:
        return "the file is not there, or is a symbolic link, or cannot be opened";
    case LC_SECRET_NOT_REGULAR:
        return "that is not a regular file";
    case LC_SECRET_NOT_OURS:
        return "the file belongs to somebody else, who can change it under us";
    case LC_SECRET_OPEN_TO_OTHERS:
        return "the file is readable beyond its owner; chmod 0600 it";
    case LC_SECRET_EMPTY:
        return "there is nothing in it";
    default:
        return "no reason recorded";
    }
}

int lc_host_port(const char *spec, char *host, size_t host_cap, uint16_t *port, uint16_t def_port)
{
    if (spec == NULL || host_cap == 0u)
        return -1;

    const char *h = spec;
    const char *colon;
    size_t      h_len;

    if (*spec == '[') {
        /* An IPv6 literal, which is the one case the last colon is not the separator. Without the
         * brackets there is nothing to separate: "2001:db8::1" split at its last colon is an address
         * with its tail read as a port, so it is refused rather than guessed at. */
        const char *close = strchr(spec, ']');
        if (close == NULL || close == spec + 1)
            return -1;
        h = spec + 1;
        h_len = (size_t)(close - h);
        colon = close[1] == ':' ? close + 1 : NULL;
        if (close[1] != '\0' && colon == NULL)
            return -1;
    } else {
        colon = strrchr(spec, ':');
        if (colon != NULL && strchr(spec, ':') != colon)
            return -1; /* more than one colon and no brackets: an address nobody wrote on purpose */
        h_len = colon != NULL ? (size_t)(colon - spec) : strlen(spec);
    }

    if (h_len == 0u || h_len >= host_cap)
        return -1;

    uint16_t p = def_port;
    if (colon == NULL && def_port == 0u)
        return -1; /* the caller said a port has to be written here, and none is */
    if (colon != NULL && lc_port(colon + 1, &p) != 0)
        return -1;

    memcpy(host, h, h_len);
    host[h_len] = '\0';
    *port = p;
    return 0;
}
