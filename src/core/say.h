/* One line, built whole, put on a descriptor in one write.
 *
 * ⚠️ THIS EXISTS BECAUSE THE ARITHMETIC BELOW WAS WRITTEN THREE TIMES IN ONE DAY, and the three
 * copies did not agree with each other: one used the buffer to its last byte and took the newline's
 * room from the terminator's slot, the other two reserved a byte up front. All three were correct —
 * checked one at a time — and that is the objection. A clamp that is wrong is a buffer overrun, so a
 * reader who meets the same idiom three times has to verify it three times, and the third reading is
 * the one that gets skipped.
 *
 * WHY ONE WRITE AT ALL, since that is the part worth keeping straight: lc-tunnel runs several
 * workers and procd hands every fork of it the SAME stdout and stderr, so they are several writers
 * on one pipe. A line delivered in more than one write comes back interleaved with theirs. What that
 * looked like on a router: a stamp alone on its line, a body with no stamp, two workers' sentences
 * spliced into one record, and tears INSIDE a single line at the boundaries between a format's
 * literal runs and its conversions — `average 3760` and `)` on different lines with another worker's
 * sentence between them.
 *
 * ⚠️ AND IT ONLY HAPPENS UNDER procd, which took four experiments to establish and is written down
 * here so that nobody repeats them. The SAME broken binary, on the SAME router, four workers, all
 * four told to print their summary at once:
 *
 *   - writing to a FILE: 56 lines, 0 torn;
 *   - writing to a pipe read by test/seam: 0 torn;
 *   - the same pipe shrunk to one page with the reader starved: 0 torn — a full pipe SERIALISES the
 *     writers, so starving the reader HIDES this fault rather than causing it, which is the opposite
 *     of what the obvious experiment assumes;
 *   - started by procd: 20 torn records out of 44;
 *   - the same procd service with the fixed binary: 44 records, 0 torn.
 *
 * Not the log daemon either — 240 messages from four concurrent `logger` processes all arrived
 * whole. And on a host it cannot be reproduced at all: glibc's line buffering puts each line on the
 * pipe in one write, so the old code was correct there. That is exactly why every gate in this tree
 * was green while a router's log was unreadable, and why there is no gate for it now.
 *
 * What it comes to is that the shape of a line's journey to the pipe depended on things this code
 * neither controls nor can see. Building the line first and writing it once removes the question
 * instead of answering it: a write of at most PIPE_BUF bytes is not interleaved with another
 * writer's, and that is a promise of the pipe rather than of whatever buffering a stdio stream ended
 * up with. LC_SAY_MAX is half of PIPE_BUF, so the promise holds with room to spare. */
#ifndef LC_SAY_H
#define LC_SAY_H

#include <stdarg.h>

/* PIPE_BUF is 4096. The longest line anything here produces is well under a quarter of this; the
 * cap is a guard against an argument off the command line, not a budget anybody writes up to. */
#define LC_SAY_MAX 2048u

/* Says one line on `fd`. The newline is added here — a format that ends in one produces a blank
 * line, which is how a caller finds out it broke the rule. */
void lc_say(int fd, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* The same, for a caller that already holds a va_list — a logging callback handed to a library, or
 * a wrapper of its own. `prefix` is copied in front of the formatted text and may be NULL; it is
 * separate from `fmt` so that a stamp cannot be mistaken for part of the caller's format, and so
 * that a caller who passes a format from elsewhere cannot have its own prefix reinterpreted.
 *
 * A line too long for the buffer is cut and SAID to be cut, ending in "...", because a sentence
 * that stops early and a sentence that had nothing more to say look identical otherwise. */
void lc_vsay(int fd, const char *prefix, const char *fmt, va_list ap);

#endif
