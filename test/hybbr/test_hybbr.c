/* The congestion control hysteria sends with, ported as patch 0009 — checked piece by piece.
 *
 * WHY A TEST AND NOT ONLY THE STAND. test/hystand/loss.sh runs both clients through the same
 * impaired path and prints what each achieved; it says whether the port is fast, not whether it is
 * the reference's algorithm. These checks ask the second question, where it can be answered
 * exactly: the arithmetic, in the reference's order of operations; the containers, with the
 * semantics the reference's own comments promise; the filter, against the three-estimate invariant
 * it is built on; and the state machine, driven by hand from STARTUP into PROBE_BW.
 *
 * The file under test is inside the patched ngtcp2 tree, so it is included as source: its functions
 * are static, which is what a controller's internals should be, and a test that can only see the
 * ngtcp2_cc vtable would be reduced to asserting that packets go in and a window comes out. */

#include <ngtcp2_hybbr.c>

#include "qgo_vectors.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
  printf("  %-4s  %s\n", cond ? "ok" : "FAIL", what);
  if (!cond) {
    ++failures;
  }
}

static void okv(int cond, const char *what, unsigned long long got,
                unsigned long long want)
{
  printf("  %-4s  %s (got %llu, want %llu)\n", cond ? "ok" : "FAIL", what, got, want);
  if (!cond) {
    ++failures;
  }
}

/* ---- the arithmetic ------------------------------------------------------------- */
static void test_arithmetic(void)
{
  printf("hybbr: the arithmetic, in the reference's order\n");

  /* core/internal/congestion/bbr/bandwidth.go:24-27 — bytes * 1e9 / delta, and only then * 8. A thousand bytes in a
   * millisecond is eight megabits per second. */
  okv(hybbr_bw_from_delta(1000, NGTCP2_MILLISECONDS) == 8000000u,
      "a thousand bytes in a millisecond is 8 Mbit/s",
      hybbr_bw_from_delta(1000, NGTCP2_MILLISECONDS), 8000000u);

  /* The order matters and this is the case that shows it: with the multiplication by eight done
   * first the truncation lands elsewhere. 3 bytes in 7 ns: (3 * 1e9 / 7) * 8 = 3428571424, where
   * 3 * 1e9 * 8 / 7 = 3428571428. */
  okv(hybbr_bw_from_delta(3, 7) == 3428571424u,
      "the division truncates before the multiplication by eight",
      hybbr_bw_from_delta(3, 7), 3428571424u);

  ok(hybbr_bw_from_delta(1000, 0) == 0, "a zero interval is no sample rather than a division");

  /* core/internal/congestion/bbr/bandwidth_sampler.go:870-874 */
  okv(hybbr_bytes_from_bw_and_delta(8000000u, NGTCP2_MILLISECONDS) == 1000u,
      "8 Mbit/s for a millisecond is a thousand bytes",
      hybbr_bytes_from_bw_and_delta(8000000u, NGTCP2_MILLISECONDS), 1000u);

  /* core/internal/congestion/bbr/bbr_sender.go:1065-1067: 10 Mbit/s with a 100 ms round trip is 125 000 bytes in flight. */
  okv(hybbr_bdp_from_rtt_and_bw(100 * NGTCP2_MILLISECONDS, 10000000u) == 125000u,
      "the BDP of 10 Mbit/s at 100 ms is 125 000 bytes",
      hybbr_bdp_from_rtt_and_bw(100 * NGTCP2_MILLISECONDS, 10000000u), 125000u);
}

/* ---- the windowed filter -------------------------------------------------------- */

/* THE SEQUENCE BELOW IS THE ALGORITHM'S, NOT AN OBVIOUS ONE, and the first version of this test got
 * it wrong in three places — which is worth saying, because the wrong version accused the port.
 *
 * A sample under the best does NOT take the second slot on arrival. After a reset all three
 * estimates hold the same value, and the second is only replaced once a QUARTER of the window has
 * passed without a better sample, the third once a HALF has (core/internal/congestion/bbr/windowed_filter.go:119-143). That is
 * the whole point of the algorithm: the second and third estimates are drawn from the second
 * quarter and the second half of the window, so that when the best ages out its replacement is
 * already a measurement from a later part of it. */
static void test_filter(void)
{
  ngtcp2_hybbr_bw_entry est[3];

  printf("\nhybbr: the three-estimate filter (windowed_filter.go)\n");

  memset(est, 0, sizeof(est));

  /* An empty filter takes the first sample into all three. */
  hybbr_bw_filter_update(est, 100, 100, 0);
  ok(est[0].sample == 100 && est[1].sample == 100 && est[2].sample == 100,
     "the first sample becomes all three estimates");

  /* A new best resets the window, whatever the times. */
  hybbr_bw_filter_update(est, 100, 200, 10);
  ok(est[0].sample == 200 && est[1].sample == 200 && est[2].sample == 200 &&
       est[0].time == 10,
     "a new best resets all three");

  /* A lower sample within the first quarter changes nothing at all. */
  hybbr_bw_filter_update(est, 100, 150, 20);
  ok(est[0].sample == 200 && est[1].sample == 200 && est[2].sample == 200,
     "a lower sample inside the first quarter is not kept");

  /* Past the quarter, it becomes the second estimate and the third with it. */
  hybbr_bw_filter_update(est, 100, 150, 40);
  ok(est[0].sample == 200 && est[1].sample == 150 && est[2].sample == 150,
     "past a quarter of the window it becomes the second and third");

  /* Past the half, a lower one becomes the third alone. */
  hybbr_bw_filter_update(est, 100, 120, 95);
  ok(est[0].sample == 200 && est[1].sample == 150 && est[2].sample == 120,
     "past a half it becomes the third alone");

  /* When the best has not been beaten for a whole window it is dropped and the others move up. */
  hybbr_bw_filter_update(est, 100, 110, 115);
  ok(est[0].sample == 150 && est[1].sample == 120 && est[2].sample == 110,
     "a best older than the window is replaced by the second, and so on down");
}

/* ---- the queue the sampler keeps sent packets in --------------------------------- */
static void test_pnq(void)
{
  ngtcp2_hybbr_pnq q;
  ngtcp2_hybbr_sent_packet sp;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  uint64_t size = 0;

  printf("\nhybbr: the packet-number queue (packet_number_indexed_queue.go)\n");

  hybbr_pnq_init(&q, mem);
  memset(&sp, 0, sizeof(sp));

  sp.size = 1;
  ok(hybbr_pnq_emplace(&q, 10, &sp) == 1, "the first packet sets the queue's origin");
  ok(q.first_packet == 10, "and it is the first packet");

  /* A gap is filled with absent entries so the index stays the packet number. */
  sp.size = 2;
  ok(hybbr_pnq_emplace(&q, 13, &sp) == 1, "a packet past the end is taken");
  ok(hybbr_pnq_get(&q, 11) == NULL && hybbr_pnq_get(&q, 12) == NULL,
     "the gap between them is absent, not zero-valued");
  ok(hybbr_pnq_get(&q, 13) != NULL && hybbr_pnq_get(&q, 13)->size == 2,
     "and the entry is where its number says");

  /* Out of order is refused rather than sorted: the caller sends in order. */
  ok(hybbr_pnq_emplace(&q, 12, &sp) == 0, "an out-of-order packet is refused");

  ok(q.number_of_present_entries == 2, "two entries are present");

  ok(hybbr_pnq_remove(&q, 13, &size) == 1 && size == 2,
     "removing an entry reports the size it held");
  ok(hybbr_pnq_get(&q, 13) == NULL, "and it is gone");

  /* Removing the first entry trims the front, which moves first_packet past every absent slot. */
  ok(hybbr_pnq_remove(&q, 10, NULL) == 1, "the first entry is removed");
  ok(hybbr_pnq_is_empty(&q), "the queue is empty");
  ok(q.first_packet == HYBBR_INVALID_PACKET_NUMBER,
     "and its origin is invalid again, as the reference leaves it");

  /* RemoveUpTo also drops absent slots, so first_packet can pass the number asked for. */
  hybbr_pnq_init(&q, mem);
  sp.size = 3;
  (void)hybbr_pnq_emplace(&q, 100, &sp);
  (void)hybbr_pnq_emplace(&q, 105, &sp);
  hybbr_pnq_remove_up_to(&q, 103);
  ok(q.first_packet == 105, "RemoveUpTo trims the absent front past the number asked for");
  ok(q.number_of_present_entries == 1, "and leaves what is still present");

  hybbr_pnq_free(&q);
}

/* ---- the ring buffer ------------------------------------------------------------- */
static void test_ring(void)
{
  ngtcp2_hybbr_ring r;
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  uint64_t v;
  int i;

  printf("\nhybbr: the ring buffer (ringbuffer.go)\n");

  hybbr_ring_init(&r, sizeof(uint64_t), mem);
  ok(hybbr_ring_empty(&r) && hybbr_ring_len(&r) == 0, "a new ring is empty");

  for (i = 0; i < 5; ++i) {
    v = (uint64_t)i;
    ok(hybbr_ring_push_back(&r, &v) == 0, i == 0 ? "it grows from nothing" : "and keeps growing");
  }

  ok(hybbr_ring_len(&r) == 5, "five in, five held");
  ok(*(uint64_t *)hybbr_ring_front(&r) == 0, "the front is the oldest");
  ok(*(uint64_t *)hybbr_ring_back(&r) == 4, "the back is the newest");
  ok(*(uint64_t *)hybbr_ring_at(&r, 2) == 2, "and an offset counts from the front");

  hybbr_ring_pop_front(&r);
  hybbr_ring_pop_front(&r);
  ok(hybbr_ring_len(&r) == 3 && *(uint64_t *)hybbr_ring_front(&r) == 2,
     "popping moves the front without moving the rest");

  /* Wrapping: push until the head has passed the end of the storage. */
  for (i = 5; i < 9; ++i) {
    v = (uint64_t)i;
    (void)hybbr_ring_push_back(&r, &v);
  }
  ok(*(uint64_t *)hybbr_ring_back(&r) == 8, "the newest is still the newest across a wrap");
  ok(*(uint64_t *)hybbr_ring_front(&r) == 2, "and the oldest is still the oldest");

  hybbr_ring_free(&r);
}

/* ---- the sampler and the state machine ------------------------------------------- */

/* A connection driven by hand: packets sent, then acknowledged, with time moved on between.
 * cstat is what ngtcp2 would keep, and the only fields this controller reads are filled. */
typedef struct {
  ngtcp2_hybbr hybbr;
  ngtcp2_conn_stat cstat;
  ngtcp2_pcg32 pcg;
  ngtcp2_tstamp now;
  int64_t next_pkt;
} harness;

static void harness_init(harness *h)
{
  memset(h, 0, sizeof(*h));
  ngtcp2_pcg32_init(&h->pcg, 42);
  h->cstat.min_rtt = UINT64_MAX;
  h->cstat.max_tx_udp_payload_size = 1280;
  h->now = 1000000000ull; /* not zero: the reference reads a zero timestamp as "never" */
  ngtcp2_hybbr_init(&h->hybbr, NULL, &h->cstat, h->now, &h->pcg, ngtcp2_mem_default(),
                    NGTCP2_INITIAL_UDP_PAYLOAD_SIZE);
}

static void harness_send(harness *h, int n, uint64_t size)
{
  ngtcp2_cc_pkt pkt;
  int i;

  for (i = 0; i < n; ++i) {
    memset(&pkt, 0, sizeof(pkt));
    pkt.pkt_num = h->next_pkt++;
    pkt.pktlen = size;
    pkt.sent_ts = h->now;

    ngtcp2_cc_hybbr_on_pkt_sent(&h->hybbr.cc, &h->cstat, &pkt);
    h->cstat.bytes_in_flight += size;
  }
}

/* Acknowledges |n| packets starting at |from|, as one ack: ngtcp2 removes them from the in-flight
 * count first, then reports each, then ends the ack — which is the order this follows. */
static void harness_ack(harness *h, int64_t from, int n, uint64_t size,
                        ngtcp2_duration rtt)
{
  ngtcp2_cc_pkt pkt;
  ngtcp2_cc_ack ack;
  int i;

  h->now += rtt;

  for (i = 0; i < n; ++i) {
    h->cstat.bytes_in_flight -= size;
  }

  if (h->cstat.min_rtt == UINT64_MAX || rtt < h->cstat.min_rtt) {
    h->cstat.min_rtt = rtt;
  }

  for (i = 0; i < n; ++i) {
    memset(&pkt, 0, sizeof(pkt));
    pkt.pkt_num = from + i;
    pkt.pktlen = size;
    ngtcp2_cc_hybbr_on_pkt_acked(&h->hybbr.cc, &h->cstat, &pkt, h->now);
  }

  memset(&ack, 0, sizeof(ack));
  ack.bytes_delivered = (uint64_t)n * size;
  ngtcp2_cc_hybbr_on_ack_recv(&h->hybbr.cc, &h->cstat, &ack, h->now);
}

static void test_machine(void)
{
  harness h;
  uint64_t cwnd0, bw;
  int round;

  printf("\nhybbr: the state machine (bbr_sender.go)\n");

  harness_init(&h);

  ok(h.hybbr.mode == HYBBR_MODE_STARTUP, "a connection starts in STARTUP");
  ok(h.hybbr.pacing_gain == HYBBR_DEFAULT_HIGH_GAIN,
     "with the startup pacing gain, 2/ln(2)");
  ok(h.hybbr.congestion_window_gain == HYBBR_DERIVED_HIGH_CWND_GAIN,
     "and the derived startup window gain, 2");
  okv(h.cstat.cwnd == 32u * 1280u, "the window starts at 32 packets of 1280 bytes",
      h.cstat.cwnd, 32u * 1280u);
  okv(h.hybbr.min_congestion_window == 4u * 1280u, "and its floor at four of them",
      h.hybbr.min_congestion_window, 4u * 1280u);

  cwnd0 = h.cstat.cwnd;

  /* Ten rounds of a steady path: ten packets out, ten acknowledged, a 20 ms round trip. That is
   * enough for the bandwidth estimate to stop growing, which is what takes a connection out of
   * STARTUP: three rounds without a 25 % gain (core/internal/congestion/bbr/bbr_sender.go:801-822). */
  for (round = 0; round < 12; ++round) {
    int64_t first = h.next_pkt;
    harness_send(&h, 10, 1280);
    harness_ack(&h, first, 10, 1280, 20 * NGTCP2_MILLISECONDS);
  }

  bw = hybbr_bandwidth_estimate(&h.hybbr);
  ok(bw > 0, "a bandwidth estimate appears");
  /* AND IT COMES DOWN, not up — which is the answer to the question this check first asked wrongly.
   *
   * BBR's window is a target computed from what it measures, not a value that ratchets: ten packets
   * of 1280 bytes acknowledged every 20 ms is 5.12 Mbit/s, whose bandwidth-delay product is 12 800
   * bytes, and the window gain outside startup is two. So a connection that started at the
   * reference's 32 packets settles at 25 600 bytes — twenty packets — because that is what this
   * path holds. A controller that only grew would be a controller that fills a buffer. */
  okv(bw == 5120000u, "the bandwidth estimate is the path's, exactly", bw, 5120000u);
  okv(hybbr_bdp_from_rtt_and_bw(hybbr_get_min_rtt(&h.hybbr), bw) == 12800u,
      "and so is the bandwidth-delay product",
      hybbr_bdp_from_rtt_and_bw(hybbr_get_min_rtt(&h.hybbr), bw), 12800u);
  okv(h.cstat.cwnd == 25600u, "the window settles at twice that product, below where it started",
      h.cstat.cwnd, 25600u);
  ok(cwnd0 == 40960u, "having started at the reference's thirty-two packets");
  ok(h.hybbr.is_at_full_bandwidth,
     "twelve rounds without a 25 % gain leave startup behind");
  ok(h.hybbr.mode == HYBBR_MODE_DRAIN || h.hybbr.mode == HYBBR_MODE_PROBE_BW,
     "and the mode is DRAIN or PROBE_BW");
  ok(h.hybbr.min_rtt == 20 * NGTCP2_MILLISECONDS,
     "the minimum round trip is the one that was measured");

  /* The pace is published in the units ngtcp2 waits by: nanoseconds per byte, times 1024. */
  ok(h.cstat.pacing_interval_m > 0, "a pacing interval is published");
  okv(h.cstat.pacing_interval_m ==
        (NGTCP2_SECONDS << 10) / hybbr_pacer_bandwidth(&h.hybbr),
      "and it is the reference's bytes-per-second inverted",
      h.cstat.pacing_interval_m,
      (NGTCP2_SECONDS << 10) / hybbr_pacer_bandwidth(&h.hybbr));
  ok(h.cstat.send_quantum == hybbr_pacer_max_burst_size(&h.hybbr),
     "the largest burst is the reference pacer's maxBurstSize");

  ngtcp2_hybbr_free(&h.hybbr);
}

static void test_loss(void)
{
  harness h;
  ngtcp2_cc_pkt pkt;
  ngtcp2_cc_ack ack;
  int round;

  printf("\nhybbr: loss and recovery (core/internal/congestion/bbr/bbr_sender.go:898-931, :1004-1036)\n");

  harness_init(&h);

  /* Out of startup first: recovery is disabled until then, exactly as the reference disables it
   * (updateRecoveryState returns early while !isAtFullBandwidth). */
  for (round = 0; round < 12; ++round) {
    int64_t first = h.next_pkt;
    harness_send(&h, 10, 1280);
    harness_ack(&h, first, 10, 1280, 20 * NGTCP2_MILLISECONDS);
  }
  ok(h.hybbr.is_at_full_bandwidth, "the connection is out of startup");
  ok(h.hybbr.recovery_state == HYBBR_RECOVERY_NOT_IN_RECOVERY, "and not in recovery");

  /* Ten out, one lost and the rest acknowledged. */
  {
    int64_t first = h.next_pkt;
    int i;

    harness_send(&h, 10, 1280);
    h.now += 20 * NGTCP2_MILLISECONDS;

    h.cstat.bytes_in_flight -= 1280; /* the lost one */
    memset(&pkt, 0, sizeof(pkt));
    pkt.pkt_num = first;
    pkt.pktlen = 1280;
    ngtcp2_cc_hybbr_on_pkt_lost(&h.hybbr.cc, &h.cstat, &pkt, h.now);

    for (i = 1; i < 10; ++i) {
      h.cstat.bytes_in_flight -= 1280;
      memset(&pkt, 0, sizeof(pkt));
      pkt.pkt_num = first + i;
      pkt.pktlen = 1280;
      ngtcp2_cc_hybbr_on_pkt_acked(&h.hybbr.cc, &h.cstat, &pkt, h.now);
    }

    memset(&ack, 0, sizeof(ack));
    ngtcp2_cc_hybbr_on_ack_recv(&h.hybbr.cc, &h.cstat, &ack, h.now);
  }

  ok(h.hybbr.recovery_state == HYBBR_RECOVERY_CONSERVATION,
     "a loss puts the connection into conservation");
  ok(h.hybbr.recovery_window >= h.hybbr.min_congestion_window,
     "and the recovery window is at least the floor");
  /* The loss is counted, and then the counter is cleared BY THE SAME EVENT, because this ack also
   * started a round: the reference clears num_loss_events_in_round and bytes_lost_in_round at the
   * end of OnCongestionEventEx when isRoundStart (core/internal/congestion/bbr/bbr_sender.go:620-623). What survives is the
   * sampler's running total, which is what the next event measures against. */
  okv(h.hybbr.sampler.total_bytes_lost == 1280u, "the lost packet's bytes reach the sampler",
      h.hybbr.sampler.total_bytes_lost, 1280u);
  ok(h.hybbr.bytes_lost_in_round == 0,
     "and the round's counter is cleared by the round this ack started");
  /* A clean round after it: conservation becomes growth, and then recovery ends. */
  {
    int64_t first = h.next_pkt;
    harness_send(&h, 10, 1280);
    harness_ack(&h, first, 10, 1280, 20 * NGTCP2_MILLISECONDS);
  }
  ok(h.hybbr.recovery_state != HYBBR_RECOVERY_CONSERVATION,
     "a round without loss moves recovery on");

  ngtcp2_hybbr_free(&h.hybbr);
}

/* ---- quic-go's NewReno, until the authentication (patches/ngtcp2/0018) ------------ */

/* A connection at the parrot's 1250 bytes, put under NewReno the way the client puts it. Before
 * the first sample ngtcp2 holds the initial RTT the client sets, 100 ms — quic-go's
 * DefaultInitialRTT (vendor/quic-go/internal/utils/rtt_stats.go:32-38). */
static void reno_init(harness *h)
{
  memset(h, 0, sizeof(*h));
  ngtcp2_pcg32_init(&h->pcg, 42);
  h->cstat.min_rtt = UINT64_MAX;
  h->cstat.smoothed_rtt = 100 * NGTCP2_MILLISECONDS;
  h->cstat.first_rtt_sample_ts = UINT64_MAX;
  h->cstat.max_tx_udp_payload_size = 1250;
  h->now = 1000000000ull;
  ngtcp2_hybbr_init(&h->hybbr, NULL, &h->cstat, h->now, &h->pcg, ngtcp2_mem_default(), 1250);
  ngtcp2_hybbr_start_reno(&h->hybbr, &h->cstat);
}

static void reno_lose(harness *h, int64_t pkt_num, uint64_t size)
{
  ngtcp2_cc_pkt pkt;

  h->cstat.bytes_in_flight -= size;
  memset(&pkt, 0, sizeof(pkt));
  pkt.pkt_num = pkt_num;
  pkt.pktlen = size;
  ngtcp2_cc_hybbr_on_pkt_lost(&h->hybbr.cc, &h->cstat, &pkt, h->now);
}

/* One step of tools/qgovec's script, and the state after it against what quic-go's cubicSender
 * printed after the same step. The RTT statistics are the reference's own, from the vector: what
 * is held to the reference here is the controller, and the estimator feeding it is test/ngpatch's
 * business. */
static int reno_step(harness *h, size_t i)
{
  const __typeof__(qgo_reno[0]) *v = &qgo_reno[i];
  uint64_t ssthresh = v->ssthresh ? v->ssthresh : UINT64_MAX;
  ngtcp2_tstamp next;
  uint64_t budget;
  int64_t k;

  switch (v->op) {
  case 'I':
    break;
  case 'S':
    if (h->next_pkt != v->a) {
      printf("        step %zu: the script sends from %lld, the harness is at %lld\n", i,
             (long long)v->a, (long long)h->next_pkt);
      return 0;
    }
    harness_send(h, (int)v->n, 1250);
    break;
  case 'A': {
    ngtcp2_cc_pkt pkt;
    ngtcp2_cc_ack ack;

    h->now += (ngtcp2_duration)v->rtt;
    h->cstat.smoothed_rtt = (ngtcp2_duration)v->srtt;
    h->cstat.latest_rtt = (ngtcp2_duration)v->latest;
    h->cstat.min_rtt = (ngtcp2_duration)v->min;
    if (h->cstat.first_rtt_sample_ts == UINT64_MAX) {
      h->cstat.first_rtt_sample_ts = h->now;
    }
    h->cstat.bytes_in_flight -= (uint64_t)v->n * 1250;
    for (k = 0; k < v->n; ++k) {
      memset(&pkt, 0, sizeof(pkt));
      pkt.pkt_num = v->a + k;
      pkt.pktlen = 1250;
      ngtcp2_cc_hybbr_on_pkt_acked(&h->hybbr.cc, &h->cstat, &pkt, h->now);
    }
    memset(&ack, 0, sizeof(ack));
    ack.rtt = (ngtcp2_duration)v->rtt;
    ack.bytes_delivered = (uint64_t)v->n * 1250;
    ngtcp2_cc_hybbr_on_ack_recv(&h->hybbr.cc, &h->cstat, &ack, h->now);
    break;
  }
  case 'L':
    reno_lose(h, v->a, 1250);
    ngtcp2_hybbr_on_loss_timer(&h->hybbr, &h->cstat, h->now);
    break;
  case 'T':
    h->now += (ngtcp2_duration)v->dt;
    break;
  }

  budget = ngtcp2_hybbr_pacer_budget(&h->hybbr, h->now);
  next = ngtcp2_hybbr_pacer_next(&h->hybbr);
  next = next ? next - 1000000000ull : 0;
  if (h->cstat.cwnd != v->cwnd || h->hybbr.reno.ssthresh != ssthresh || budget != v->budget ||
      next != (ngtcp2_tstamp)v->next) {
    printf("        step %zu '%c': cwnd %llu ssthresh %llu budget %llu next %llu; quic-go %llu %llu "
           "%llu %llu\n",
           i, v->op, (unsigned long long)h->cstat.cwnd, (unsigned long long)h->hybbr.reno.ssthresh,
           (unsigned long long)budget, (unsigned long long)next, (unsigned long long)v->cwnd,
           (unsigned long long)ssthresh, (unsigned long long)v->budget,
           (unsigned long long)v->next);
    return 0;
  }
  return 1;
}

static void test_reno(void)
{
  harness h;
  ngtcp2_cc_ack ack;

  printf("\nhybbr: quic-go's NewReno before the authentication (internal/congestion/cubic_sender.go)\n");

  reno_init(&h);
  ok(h.hybbr.reno.on, "the connection starts under NewReno");
  okv(h.cstat.cwnd == 32u * 1250u, "at 32 datagrams of the connection's 1250 bytes",
      h.cstat.cwnd, 32u * 1250u);
  /* Before the first sample quic-go's SmoothedRTT is 100 ms, not zero: the pacer runs at 5/4 of
   * 32 datagrams per 100 ms, two milliseconds of which is a thousand bytes, and its burst is the
   * floor of ten InitialPacketSize datagrams. */
  okv(ngtcp2_hybbr_pacer_budget(&h.hybbr, h.now) == 12800u,
      "the pacer's first burst is ten datagrams of 1280 bytes",
      ngtcp2_hybbr_pacer_budget(&h.hybbr, h.now), 12800u);

  /* The whole script, step by step against quic-go (tools/qgovec/congestion_test.go): slow start
   * window-limited and not, a loss and a second from the same flight, recovery, congestion
   * avoidance, the pacer's budget and next send time after each. */
  {
    size_t i, n = sizeof(qgo_reno) / sizeof(qgo_reno[0]), done = 0;

    reno_init(&h);
    for (i = 0; i < n && reno_step(&h, i); ++i) {
      ++done;
    }
    okv(done == n, "every step of quic-go's NewReno script gives its window, threshold and pacer",
        done, n);
  }

  /* Slow start, window-limited: thirty out (more than half the window), ten acknowledged — one
   * datagram's growth for each. */
  reno_init(&h);
  harness_send(&h, 30, 1250);
  harness_ack(&h, 0, 10, 1250, 20 * NGTCP2_MILLISECONDS);
  okv(h.cstat.cwnd == 42u * 1250u, "slow start adds a datagram per acknowledged packet",
      h.cstat.cwnd, 42u * 1250u);

  /* Application-limited: five out of a window of thirty-two grows nothing (isCwndLimited). */
  reno_init(&h);
  harness_send(&h, 5, 1250);
  harness_ack(&h, 0, 5, 1250, 20 * NGTCP2_MILLISECONDS);
  okv(h.cstat.cwnd == 32u * 1250u, "an application-limited sender does not grow its window",
      h.cstat.cwnd, 32u * 1250u);

  /* Loss: the window times renoBeta, once per window — a second packet from the same flight changes
   * nothing, since it was sent before the cutback. */
  reno_init(&h);
  harness_send(&h, 10, 1250);
  reno_lose(&h, 3, 1250);
  memset(&ack, 0, sizeof(ack));
  ack.rtt = UINT64_MAX;
  ngtcp2_cc_hybbr_on_ack_recv(&h.hybbr.cc, &h.cstat, &ack, h.now);
  okv(h.cstat.cwnd == 28000u, "a loss takes the window to 0.7 of itself", h.cstat.cwnd, 28000u);
  okv(h.cstat.ssthresh == 28000u, "and slow start ends there", h.cstat.ssthresh, 28000u);
  reno_lose(&h, 5, 1250);
  ngtcp2_cc_hybbr_on_ack_recv(&h.hybbr.cc, &h.cstat, &ack, h.now);
  okv(h.cstat.cwnd == 28000u, "a second loss from the same flight is the same event",
      h.cstat.cwnd, 28000u);

  /* A loss the TIMER finds reaches the controller when it is found, not with the next ACK. */
  reno_init(&h);
  harness_send(&h, 10, 1250);
  reno_lose(&h, 2, 1250);
  ngtcp2_hybbr_on_loss_timer(&h.hybbr, &h.cstat, h.now);
  okv(h.cstat.cwnd == 28000u, "a loss the timer declares cuts the window at once",
      h.cstat.cwnd, 28000u);

  /* And the accepted authentication: a new BBR, from nothing. */
  ngtcp2_cc_hybbr_reset(&h.hybbr.cc, &h.cstat, h.now);
  ok(!h.hybbr.reno.on, "the reset leaves NewReno");
  ok(h.hybbr.mode == HYBBR_MODE_STARTUP, "for a BBR in STARTUP");

  ngtcp2_hybbr_free(&h.hybbr);
}

int main(void)
{
  test_arithmetic();
  test_filter();
  test_pnq();
  test_ring();
  test_machine();
  test_loss();
  test_reno();

  printf("\n%s\n", failures == 0 ? "all good" : "FAILURES");

  return failures == 0 ? 0 : 1;
}
