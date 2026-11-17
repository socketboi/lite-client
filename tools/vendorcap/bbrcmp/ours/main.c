/* THE PORT, driven through the same scripted sequence as the reference, printing the same fields.
 *
 * Its twin is ref/main.go. The script below and the one there have to say the same thing, and the
 * only way to keep them saying it is that both are short enough to read side by side: fourteen
 * rounds of ten packets out and ten acknowledged a round trip later, then one round with a loss.
 *
 * The controller is included as source, exactly as test/hybbr includes it: its state is what is being
 * compared, and the ngtcp2_cc vtable does not expose it. */
#include <ngtcp2_hybbr.c>

#include <stdio.h>
#include <string.h>

#define PACKET     1280u
#define PER_ROUND  10
#define RTT        (20 * NGTCP2_MILLISECONDS)
#define ROUNDS     14

static ngtcp2_hybbr    hybbr;
static ngtcp2_conn_stat cstat;
static ngtcp2_pcg32     pcg;
static ngtcp2_tstamp    now;
static int64_t          pn;

/* THE SAME DIE ROLL AS THE REFERENCE'S, held rather than matched by luck.
 *
 * Entering PROBE_BW draws a cycle offset, and the offset decides the pacing gain (1.25 for zero, 1.0
 * for two through seven). run.sh pins the reference's draw to zero in its scratch copy; this finds
 * the seed whose first draw gives zero here, so the two agree about the one number neither can
 * predict. Everything else the cycle does is compared as it is. */
static uint64_t seed_for_offset_zero(void)
{
  uint64_t seed;

  for (seed = 1; seed < 100000; ++seed) {
    ngtcp2_pcg32 t;
    uint32_t     r;

    ngtcp2_pcg32_init(&t, seed);
    r = ngtcp2_pcg32_rand(&t) % HYBBR_PACKETS_PER_CONNECTION_ID;

    if ((int)(r % (HYBBR_GAIN_CYCLE_LENGTH - 1)) == 0) {
      return seed;
    }
  }

  fprintf(stderr, "bbrcmp: no seed in 100000 draws a zero offset\n");
  return 1;
}

static void line(int round)
{
  printf("round %02d cwnd=%llu pacing=%llu slowstart=%d recovery=%d\n", round,
         (unsigned long long)hybbr_get_cwnd(&hybbr),
         (unsigned long long)hybbr_pacing_rate(&hybbr),
         hybbr.mode == HYBBR_MODE_STARTUP ? 1 : 0,
         hybbr.recovery_state != HYBBR_RECOVERY_NOT_IN_RECOVERY ? 1 : 0);
}

/* One packet out. ngtcp2 reports a packet BEFORE adding it to the in-flight count and the reference
 * is told the count WITH it, which the controller's on_pkt_sent accounts for — so the caller here
 * does what ngtcp2 does: report first, then add. */
static void send_one(void)
{
  ngtcp2_cc_pkt pkt;

  memset(&pkt, 0, sizeof(pkt));
  pkt.pkt_num = pn++;
  pkt.pktlen = PACKET;
  pkt.sent_ts = now;

  ngtcp2_cc_hybbr_on_pkt_sent(&hybbr.cc, &cstat, &pkt);
  cstat.bytes_in_flight += PACKET;
}

/* An ack, in the order ngtcp2 delivers one: every acknowledged and lost packet is out of the
 * in-flight count before the first report, the losses are reported next, and the ack ends last. */
static void ack_round(int64_t first, int skip_first, int with_loss)
{
  ngtcp2_cc_pkt pkt;
  ngtcp2_cc_ack ack;
  int           i;

  now += RTT;

  if (cstat.min_rtt == UINT64_MAX || RTT < cstat.min_rtt) {
    cstat.min_rtt = RTT;
  }

  for (i = 0; i < PER_ROUND; ++i) {
    cstat.bytes_in_flight -= PACKET;
  }

  if (with_loss) {
    memset(&pkt, 0, sizeof(pkt));
    pkt.pkt_num = first;
    pkt.pktlen = PACKET;
    ngtcp2_cc_hybbr_on_pkt_lost(&hybbr.cc, &cstat, &pkt, now);
  }

  for (i = skip_first; i < PER_ROUND; ++i) {
    memset(&pkt, 0, sizeof(pkt));
    pkt.pkt_num = first + i;
    pkt.pktlen = PACKET;
    ngtcp2_cc_hybbr_on_pkt_acked(&hybbr.cc, &cstat, &pkt, now);
  }

  memset(&ack, 0, sizeof(ack));
  ngtcp2_cc_hybbr_on_ack_recv(&hybbr.cc, &cstat, &ack, now);
}

int main(void)
{
  int     round;
  int64_t first;

  memset(&cstat, 0, sizeof(cstat));
  cstat.min_rtt = UINT64_MAX;
  cstat.max_tx_udp_payload_size = PACKET;

  ngtcp2_pcg32_init(&pcg, seed_for_offset_zero());
  now = 1000000000ull;

  ngtcp2_hybbr_init(&hybbr, NULL, &cstat, now, &pcg, ngtcp2_mem_default());

  for (round = 1; round <= ROUNDS; ++round) {
    int i;

    first = pn;
    for (i = 0; i < PER_ROUND; ++i) {
      send_one();
    }

    ack_round(first, 0, 0);
    line(round);
  }

  first = pn;
  {
    int i;
    for (i = 0; i < PER_ROUND; ++i) {
      send_one();
    }
  }
  ack_round(first, 1, 1);
  line(ROUNDS + 1);

  ngtcp2_hybbr_free(&hybbr);

  return 0;
}
