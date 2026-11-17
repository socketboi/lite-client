#include "core/say.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void lc_vsay(int fd, const char *prefix, const char *fmt, va_list ap)
{
    char line[LC_SAY_MAX];

    /* The last byte of the buffer belongs to the newline and to nothing else, so everything below
     * measures itself against `cap` and the newline can always be put on afterwards. */
    const size_t cap = sizeof line - 1u;
    size_t       n = 0;

    if (prefix != NULL) {
        size_t plen = strlen(prefix);
        n = (plen < cap) ? plen : cap - 1u;
        memcpy(line, prefix, n);
    }

    int m = vsnprintf(line + n, cap - n, fmt, ap);
    if (m < 0) {
        /* An encoding failure. The line still goes out: a caller that meant to say something and a
         * caller that said nothing are worth telling apart, and silence here would look like the
         * event never happened. */
        static const char broke[] = "(this line could not be formatted)";
        size_t            room = cap - n;
        size_t            k = sizeof broke - 1u;
        if (k > room)
            k = room;
        memcpy(line + n, broke, k);
        n += k;
    } else if ((size_t)m < cap - n) {
        n += (size_t)m;
    } else {
        /* vsnprintf reports the length it WANTED, so this is the truncated case: take what it
         * actually wrote and mark the cut. */
        n = cap;
        if (n >= 3u)
            memcpy(line + n - 3u, "...", 3u);
    }

    line[n++] = '\n';

    /* Retried only on EINTR. At this length the kernel takes all of it or none of it, so a short
     * count is not a case that exists here and a loop over it would be a loop that never runs. */
    ssize_t w;
    do {
        w = write(fd, line, n);
    } while (w < 0 && errno == EINTR);
    (void)w;
}

void lc_say(int fd, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    lc_vsay(fd, NULL, fmt, ap);
    va_end(ap);
}
