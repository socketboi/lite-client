/* What a thread does in one turn of a spin: the processor's own hint that it is waiting — `yield`
 * on ARM, `pause` on x86 — and on MIPS only a compiler barrier, since `yield` there belongs to the
 * MT extension and the routers' toolchain builds for the base instruction set. Shared by the send
 * queue's writer, awake for a while before it sleeps, and the loop, waiting out the last datagrams
 * the openers of quic/rxopen.c still hold. */
#ifndef LC_RELAX_H
#define LC_RELAX_H

static inline void lc_cpu_relax(void)
{
#if defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#else
    __asm__ __volatile__("" ::: "memory");
#endif
}

#endif
