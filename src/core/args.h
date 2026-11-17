/* Reading the things a command line hands over.
 *
 * Four programs took the same public key, the same short id and the same fingerprint table, and
 * each carried its own copy of the code that reads them. Identical on the day they were written,
 * and the kind of thing that stops being identical quietly: REALITY's public key is accepted in two
 * spellings, hex and base64url, and a third would have reached whichever copies somebody
 * remembered. */
#ifndef LC_ARGS_H
#define LC_ARGS_H

#include <stddef.h>
#include <stdint.h>

/* ---- what a tool's exit status means -----------------------------------------------------------
 *
 * Stated once, here, because it was decided eight times separately and came out three different
 * ways: lc-xfetch answered "the node took us for a stranger" with 1 where lc-probe and lc-fetch
 * answered 2, and the REALITY tools answered a bad port with 2 and a bad public key — the same class
 * of mistake, one argument along — with 1. A script that branches on the status was therefore
 * branching on which file the code happened to be written in.
 *
 * The line the three values draw is between "this run could not have worked" and "it could have,
 * and the network said no":
 *
 *   0  it worked.
 *   1  the run failed out on the network: nothing answered, the handshake timed out, the stream
 *      ended, nothing came back. Retrying later is a sensible thing to do.
 *   2  the run never had a chance, and retrying will do the same thing again — an argument that
 *      cannot mean what it says, a secret that cannot be read, or a node that answered and did not
 *      accept us as its own (REALITY not authenticated, a password refused). All of these are
 *      configuration, whether it was typed on the command line or set on the node.
 *
 * A tool that cannot say which of the two it hit says 1, because "try again" is the harmless
 * mistake and "stop retrying, this is broken" is not. */
#define LC_EXIT_OK 0
#define LC_EXIT_FAILED 1
#define LC_EXIT_CONFIG 2

/* Exactly `out_len` bytes from exactly twice that many hex digits. Returns 0 or -1; a short string
 * is refused rather than padded, because a key half read is a key that authenticates nothing. */
int lc_from_hex(const char *s, uint8_t *out, size_t out_len);

/* The same, from unpadded base64url — the spelling Xray prints REALITY keys in. */
int lc_from_base64url(const char *s, uint8_t *out, size_t out_len);

/* A TCP or UDP port: 1 to 65535, every character a digit, nothing after it. Returns 0, or -1 with
 * `*out` untouched.
 *
 * Written because atoi answers anyway. Handed "127.0.0.1:11081" — a listen argument spelled as
 * host:port when it takes a bare port — atoi returns 127, and the tool binds port 127 and reports
 * that it is listening, which is true and useless: the connection that was meant to arrive never
 * does, and the failure looks like the tunnel rather than the argument. The same silence covers a
 * port of 0 (bind picks one at random), a negative one, and a trailing typo. */
int lc_port(const char *s, uint16_t *out);

/* A whole non-negative number, every character a digit, nothing before or after it, refused rather
 * than wrapped when it will not fit. Returns 0, or -1 with `*out` untouched.
 *
 * Written because strtoull answers anyway, and the answer it gives is the dangerous kind. The
 * Hysteria2 tools took their receive rate with it: "100mbps" — the spelling hysteria's own config
 * uses — parsed as 100, and "abc" as 0, and neither was reported. A rate of zero is not a small
 * rate, it is Brutal switched OFF at the node, so the tool then measured ordinary congestion control
 * and printed the number as though it were the protocol's. The one measurement anybody takes of this
 * client was wrong, and nothing on the way said so. */
int lc_u64(const char *s, uint64_t *out);

/* The same, bounded to sixteen bits. Unlike lc_port, zero is a value rather than an error: a DNS
 * query type is a number in that range and nothing more.
 *
 * lc-hydns read its type with atoi, which made "AAAA" mean type 0 and "-1" mean 65535 after the
 * conversion to unsigned — a question that goes out, gets an answer, and is not the question that
 * was asked. */
int lc_u16(const char *s, uint16_t *out);

/* "host", "host:port", "[v6::addr]" or "[v6::addr]:port" — the shape every tool takes its target in.
 * The host goes into `host` (never longer than `host_cap`, brackets removed), the port into `*port`,
 * and `def_port` is what stands in when the spec carries none — pass 0 to mean that one has to be
 * written. Returns 0, or -1 with both untouched.
 *
 * Seven copies of this existed, none of them the same and none of them checked. The common one split
 * at the last colon and pasted the halves back together without looking at either, so
 * "example.com:htp" travelled to the node as a port it would refuse, "example.com:" as an empty one,
 * and an IPv6 literal typed without brackets was cut in the middle of the address. The test suite
 * could not see any of it: the copies never reached lc_port, which is the only part that was
 * tested. */
int lc_host_port(const char *spec, char *host, size_t host_cap, uint16_t *port, uint16_t def_port);

/* A whole file, or -1 if it does not fit in `cap`. Truncation is a failure rather than a short
 * read: half a fingerprint table builds a ClientHello that no browser has ever sent. */
long lc_read_file(const char *path, uint8_t *dst, size_t cap);

/* Why a secret could not be read. One value per cause, because the caller printing "cannot read the
 * password" for all of them sent everybody to check file modes when the file was simply empty — and
 * the one cause that IS a mode problem is then indistinguishable from the four that are not. */
#define LC_SECRET_OK 0
#define LC_SECRET_TOO_LONG (-1)
#define LC_SECRET_NO_FILE (-2)
#define LC_SECRET_NOT_REGULAR (-3)
#define LC_SECRET_OPEN_TO_OTHERS (-4)
#define LC_SECRET_EMPTY (-5)
#define LC_SECRET_NOT_OURS (-6)
/* A NUL inside the line. Its own answer rather than one of the above, because the shape of the
 * mistake is specific: a file saved as UTF-16, or one that a tool wrote a terminator into. Read as a
 * C string it looks like a short, perfectly valid secret, which is the worst of the outcomes here —
 * see the note at the read itself. */
#define LC_SECRET_HAS_NUL (-7)

/* A secret, either written out or read from a file named with a leading @. Returns LC_SECRET_OK, or
 * one of the negative codes above; every caller may keep testing `!= 0`.
 *
 * Anything on a command line is readable by every process on the machine through /proc, and a
 * password or an account is the whole credential — so the file form is what a deployment should
 * use, and the literal stays only because it is what makes a one-line test possible.
 *
 * The two forms accept exactly the same secrets. They did not: a line that ended exactly at the
 * buffer's last character was refused from a file and accepted as a literal, and an empty one was
 * refused from a file and accepted as a literal — so a working password could be rejected by moving
 * it into the file the deployment is told to use.
 *
 * A line that fills the buffer without ending is refused rather than truncated: a secret cut short
 * is a wrong secret, and what a node does with a wrong secret is answer as though it were an
 * ordinary web server.
 *
 * The file is opened without following a symbolic link, has to be a regular file, and has to be
 * closed to group and to everyone else. The bare fopen this used to be would follow a link somebody
 * else had put in place of the file, read the first line of whatever it pointed at, and send it to
 * the node as the password — with the configuration file still saying, as a wish rather than a fact,
 * "Mode 0600, owned by root". */
int lc_read_secret(const char *arg, char *out, size_t cap);

/* The English of one of those codes, for the message the operator actually reads. */
const char *lc_secret_why(int rc);

#endif
