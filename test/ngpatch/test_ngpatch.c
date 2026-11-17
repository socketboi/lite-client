/* The patches to ngtcp2, held to what quic-go COMPUTES — one check per rule, each against vectors
 * the reference's own code produced on the same inputs (tools/qgovec, laid into vendor/quic-go
 * through `go test -overlay` and run there).
 *
 * WHY THIS AND NOT ONLY THE STANDS. tools/vendorcap/qstand and test/hystand compare the two clients
 * on the wire, and they are what found most of these rules — but they run by hand, they need the
 * reference built, and a stand that reads "the same" says nothing about the case it did not happen
 * to exercise. These run in the gate on every commit, and each asks one rule a question it can
 * only answer one way: the packet-number length, the long header's Length field, the first
 * Initial of a client parroting Chrome, the Destination Connection ID a client moves to, the
 * receive windows it advertises, which packets it declares lost and the order it resends them in,
 * which it marks ECT(0) and what it decides from the ECN counts it is sent back.
 * Every one of them was held against a mutant that reverts its rule, and failed.
 *
 * The connection is ngtcp2's own client with null crypto, as ngtcp2's tests drive it
 * (null_encrypt to null_hp_mask and fake_crypto_ctx, vendor/ngtcp2/tests/ngtcp2_conn_test.c:158-285;
 * setup_default_client_with_options, :1212-1253), and the server's packets are made by its test
 * encoder (vendor/ngtcp2/tests/ngtcp2_test_helper.c). ngtcp2_conn.c is included as source, from
 * the PATCHED tree, so the rules' own static functions are in reach as well as the connection they
 * run in. */

#include <ngtcp2_conn.c>

#include "ngtcp2_test_helper.h"
#include "qgo_vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void ok(int cond, const char *what)
{
  printf("  %s  %s\n", cond ? "ok  " : "FAIL", what);
  if (!cond) {
    ++failures;
  }
}

static void okv(int cond, const char *what, unsigned long long got, unsigned long long want)
{
  printf("  %s  %s (got %llu, want %llu)\n", cond ? "ok  " : "FAIL", what, got, want);
  if (!cond) {
    ++failures;
  }
}

/* ---- null crypto, as ngtcp2's tests have it ------------------------------------------ */

static uint8_t null_secret[32];
static uint8_t null_iv[16];
static uint8_t null_data[65536];
static const ngtcp2_crypto_aead_ctx null_aead_ctx;
static const ngtcp2_crypto_cipher_ctx null_hp_ctx;
static const ngtcp2_crypto_ctx fake_crypto_ctx = {
  .aead.max_overhead = NGTCP2_FAKE_AEAD_OVERHEAD,
  .max_encryption = 9999,
  .max_decryption_failure = 8888,
};
static const ngtcp2_crypto_ctx fake_initial_crypto_ctx = {
  .aead.max_overhead = NGTCP2_INITIAL_AEAD_OVERHEAD,
  .max_encryption = 9999,
  .max_decryption_failure = 8888,
};
static ngtcp2_path_storage test_path;
/* The last packet number the test server used; client_new starts it over. */
static int64_t server_last_pn;
static size_t hello_len = 217;

static int t_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                     const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *plaintext,
                     size_t plaintextlen, const uint8_t *nonce, size_t noncelen,
                     const uint8_t *aad, size_t aadlen)
{
  (void)aead; (void)aead_ctx; (void)nonce; (void)noncelen; (void)aad; (void)aadlen;
  if (plaintextlen && plaintext != dest) {
    memcpy(dest, plaintext, plaintextlen);
  }
  memset(dest + plaintextlen, 0, NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int t_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                     const ngtcp2_crypto_aead_ctx *aead_ctx, const uint8_t *ciphertext,
                     size_t ciphertextlen, const uint8_t *nonce, size_t noncelen,
                     const uint8_t *aad, size_t aadlen)
{
  (void)aead; (void)aead_ctx; (void)nonce; (void)noncelen; (void)aad; (void)aadlen;
  memmove(dest, ciphertext, ciphertextlen - NGTCP2_FAKE_AEAD_OVERHEAD);
  return 0;
}

static int t_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                     const ngtcp2_crypto_cipher_ctx *hp_ctx, const uint8_t *sample)
{
  (void)hp; (void)hp_ctx; (void)sample;
  memset(dest, 0, NGTCP2_HP_MASKLEN);
  return 0;
}

/* Any bytes do, as long as they are not all the same: the connection seeds its PCG from them —
 * except where a test wants every byte one value (rand_fill), as the skipping test does. */
static int rand_fill = -1;

static void t_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
  static uint32_t x = 2463534242u;
  size_t i;

  (void)rand_ctx;
  if (rand_fill >= 0) {
    memset(dest, rand_fill, destlen);
    return;
  }
  for (i = 0; i < destlen; ++i) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    dest[i] = (uint8_t)x;
  }
}

static int t_new_cid(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                     size_t cidlen, void *user_data)
{
  (void)user_data;
  *cid = (ngtcp2_cid){ .datalen = cidlen, .data = { 0xee, (uint8_t)(conn->scid.last_seq + 1) } };
  *token = (ngtcp2_stateless_reset_token){ 0 };
  return 0;
}

static int t_update_key(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret,
                        ngtcp2_crypto_aead_ctx *rx_aead_ctx, uint8_t *rx_iv,
                        ngtcp2_crypto_aead_ctx *tx_aead_ctx, uint8_t *tx_iv,
                        const uint8_t *current_rx_secret, const uint8_t *current_tx_secret,
                        size_t secretlen, void *user_data)
{
  (void)conn; (void)rx_secret; (void)tx_secret; (void)rx_aead_ctx; (void)rx_iv;
  (void)tx_aead_ctx; (void)tx_iv; (void)current_rx_secret; (void)current_tx_secret;
  (void)secretlen; (void)user_data;
  return 0;
}

static void t_del_aead(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *c, void *u)
{
  (void)conn; (void)c; (void)u;
}

static void t_del_cipher(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *c, void *u)
{
  (void)conn; (void)c; (void)u;
}

static int t_path_challenge(ngtcp2_conn *conn, ngtcp2_path_challenge_data *data, void *u)
{
  (void)conn; (void)u;
  memset(data, 0, sizeof(*data));
  return 0;
}

static int t_recv_crypto(ngtcp2_conn *conn, ngtcp2_encryption_level lvl, uint64_t offset,
                         const uint8_t *data, size_t datalen, void *u)
{
  (void)conn; (void)lvl; (void)offset; (void)data; (void)datalen; (void)u;
  return 0;
}

static int t_recv_retry(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *u)
{
  (void)conn; (void)hd; (void)u;
  return 0;
}

/* The ClientHello: hello_len bytes of nothing, at the Initial level. */
static int t_client_initial(ngtcp2_conn *conn, void *u)
{
  (void)u;
  ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, null_data, hello_len);
  return 0;
}

static void callbacks(ngtcp2_callbacks *cb)
{
  *cb = (ngtcp2_callbacks){
    .client_initial = t_client_initial,
    .recv_retry = t_recv_retry,
    .recv_crypto_data = t_recv_crypto,
    .encrypt = t_encrypt,
    .decrypt = t_decrypt,
    .hp_mask = t_hp_mask,
    .rand = t_rand,
    .get_new_connection_id2 = t_new_cid,
    .update_key = t_update_key,
    .delete_crypto_aead_ctx = t_del_aead,
    .delete_crypto_cipher_ctx = t_del_cipher,
    .get_path_challenge_data2 = t_path_challenge,
  };
}

/* The server's first Connection ID, and the ones it issues: 0xc0 then zeroes then the sequence
 * number, as tools/qgovec makes them. */
static ngtcp2_cid cid_of(uint8_t seq)
{
  ngtcp2_cid c = { .datalen = 8, .data = { 0xc0, 0, 0, 0, 0, 0, 0, seq } };
  return c;
}

static ngtcp2_conn *client_new(int chrome, const ngtcp2_transport_params *params_in)
{
  ngtcp2_conn *conn = NULL;
  ngtcp2_callbacks cb;
  ngtcp2_settings settings;
  ngtcp2_transport_params params;
  ngtcp2_cid dcid = cid_of(0);
  /* The client's own Connection ID: empty when it parrots Chrome, four bytes otherwise, as
   * src/quic/conn.c chooses them. */
  ngtcp2_cid scid = { .datalen = chrome ? 0 : 4, .data = { 0xcc, 1, 2, 3 } };

  callbacks(&cb);
  ngtcp2_settings_default(&settings);
  settings.initial_ts = 0;
  settings.initial_rtt = 100 * NGTCP2_MILLISECONDS;
  settings.cc_algo = NGTCP2_CC_ALGO_HYBBR;
  settings.chrome_parrot = (uint8_t)chrome;
  settings.max_window = 20971520;
  settings.max_stream_window = 8388608;
  if (params_in) {
    params = *params_in;
  } else {
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 4;
    params.initial_max_stream_data_bidi_local = 6291456;
    params.initial_max_stream_data_bidi_remote = 6291456;
    params.initial_max_data = 15728640;
    params.active_connection_id_limit = 4;
  }
  path_init(&test_path, 0, 0, 0, 0);
  server_last_pn = -1;

  if (ngtcp2_conn_client_new(&conn, &dcid, &scid, &test_path.path, NGTCP2_PROTO_VER_V1, &cb,
                             &settings, &params, NULL, NULL) != 0) {
    return NULL;
  }
  ngtcp2_conn_set_initial_crypto_ctx(conn, &fake_initial_crypto_ctx);
  ngtcp2_conn_install_initial_key(conn, &null_aead_ctx, null_iv, &null_hp_ctx, &null_aead_ctx,
                                  null_iv, &null_hp_ctx, sizeof(null_iv));
  return conn;
}

/* A client past its handshake, as ngtcp2's own tests put one there
 * (setup_default_client_with_options, vendor/ngtcp2/tests/ngtcp2_conn_test.c:1212-1253) — except
 * that HANDSHAKE_COMPLETED is left for the test to set, since one rule here is about exactly that
 * moment. */
static ngtcp2_conn *client_established(void)
{
  ngtcp2_conn *conn = client_new(0, NULL);
  ngtcp2_transport_params remote;

  ngtcp2_conn_set_crypto_ctx(conn, &fake_crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(conn, &null_aead_ctx, null_iv, sizeof(null_iv),
                                       &null_hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &null_aead_ctx, null_iv, sizeof(null_iv),
                                       &null_hp_ctx);
  ngtcp2_conn_install_rx_key(conn, null_secret, sizeof(null_secret), &null_aead_ctx, null_iv,
                             sizeof(null_iv), &null_hp_ctx);
  ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &null_aead_ctx, null_iv,
                             sizeof(null_iv), &null_hp_ctx);
  conn->state = NGTCP2_CS_POST_HANDSHAKE;
  conn->flags |= NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED | NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                 NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  conn->dcid.current.flags |= NGTCP2_DCID_FLAG_PATH_VALIDATED;
  conn->negotiated_version = conn->client_chosen_version;

  ngtcp2_transport_params_default(&remote);
  remote.initial_max_stream_data_bidi_local = 8388608;
  remote.initial_max_stream_data_bidi_remote = 8388608;
  remote.initial_max_stream_data_uni = 8388608;
  remote.initial_max_data = 20971520;
  remote.initial_max_streams_bidi = 100;
  remote.initial_max_streams_uni = 100;
  remote.active_connection_id_limit = 8;
  remote.initial_scid = conn->dcid.current.cid;
  remote.initial_scid_present = 1;
  remote.original_dcid = conn->rcid;
  remote.original_dcid_present = 1;
  ngtcp2_conn_set_remote_transport_params(conn, &remote);

  /* The RTT the flow controllers read: the vectors' own. */
  conn->cstat.smoothed_rtt = (ngtcp2_duration)QGO_FLOW_SRTT_NS;
  conn->cstat.latest_rtt = (ngtcp2_duration)QGO_FLOW_SRTT_NS;
  conn->cstat.min_rtt = (ngtcp2_duration)QGO_FLOW_SRTT_NS;
  conn->cstat.first_rtt_sample_ts = 1;
  /* Confirmed from the start, as ngtcp2's own tests have it: the loss detection reads when. */
  conn->handshake_confirmed_ts = 0;
  /* No packet number is skipped: the scripts number their packets one after another, and the
   * skipping is a rule of its own. */
  conn->pktns.tx.skip_pkt.next_pkt_num = INT64_MAX;
  return conn;
}
static int server_sends(ngtcp2_conn *conn, ngtcp2_frame *fr, size_t nfr, ngtcp2_tstamp ts);


/* No RTT sample yet, as a fresh connection has it: the scripts that measure one start here, so that
 * their first sample is the first, as it is in quic-go's. */
static void rtt_unsampled(ngtcp2_conn *conn)
{
  conn->cstat.min_rtt = UINT64_MAX;
  conn->cstat.first_rtt_sample_ts = UINT64_MAX;
  conn->cstat.smoothed_rtt = 100 * NGTCP2_MILLISECONDS;
  conn->cstat.rttvar = 50 * NGTCP2_MILLISECONDS;
  conn->cstat.latest_rtt = 0;
}

/* One packet of |len| bytes of stream |sid| written at |*ts|, or as soon after as the pacer lets
 * it go, in steps of a microsecond. Returns the packet's number. */
static int64_t client_sends(ngtcp2_conn *conn, int64_t sid, size_t len, ngtcp2_tstamp *ts)
{
  static uint8_t buf[2048];
  ngtcp2_vec v = { null_data, len };
  int i;

  for (i = 0; i < 100000; ++i, *ts += NGTCP2_MICROSECONDS) {
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize n = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                               NGTCP2_WRITE_STREAM_FLAG_NONE, sid, &v, 1, *ts);
    if (n > 0) {
      return conn->pktns.tx.last_pkt_num;
    }
  }
  return -1;
}

/* The server acknowledges packets [lo, hi] of the client's, at |ts|, the ACK Delay field saying
 * |delay|. */
static int server_acks(ngtcp2_conn *conn, int64_t lo, int64_t hi, ngtcp2_duration delay,
                       ngtcp2_tstamp ts)
{
  ngtcp2_frame fr;

  fr.ack = (ngtcp2_ack){
    .type = NGTCP2_FRAME_ACK,
    .largest_ack = hi,
    .ack_delay = delay / NGTCP2_MICROSECONDS / 8, /* the default ack_delay_exponent, 3 */
    .first_ack_range = (uint64_t)(hi - lo),
  };
  return server_sends(conn, &fr, 1, ts);
}

/* A 1-RTT packet from the server, carrying |fr|, read by the client at |ts|. */
/* Header flags for the server's next packets, as a test sets them: the key phase, after a key update
 * the server has followed. */
static uint8_t server_pkt_flags;

static int server_sends(ngtcp2_conn *conn, ngtcp2_frame *fr, size_t nfr, ngtcp2_tstamp ts)
{
  static uint8_t buf[65536];
  ngtcp2_tpe tpe;
  ngtcp2_pkt_info pi = { 0 };
  size_t n;

  ngtcp2_tpe_init_conn(&tpe, conn);
  tpe.flags |= server_pkt_flags;
  tpe.app.last_pkt_num = server_last_pn;
  n = ngtcp2_tpe_write_1rtt(&tpe, buf, sizeof(buf), fr, nfr);
  server_last_pn = tpe.app.last_pkt_num;
  return ngtcp2_conn_read_pkt(conn, &test_path.path, &pi, buf, n, ts);
}

/* What one written 1-RTT packet carried. */
typedef struct {
  uint8_t dcid_last;
  size_t pnlen;
  size_t nretire;
  uint64_t retire_seq[4];
  uint64_t max_data, max_stream_data;
  int64_t stream_ids[16];
  uint64_t stream_offsets[16];
  uint64_t stream_lens[16];
  size_t nstreams;
  /* STREAMS_BLOCKED (bidi) frames, and the limit the last one carried. */
  size_t nblocked;
  uint64_t blocked_limit;
} written;

static int parse_short(ngtcp2_conn *conn, const uint8_t *p, size_t n, written *w)
{
  ngtcp2_pkt_hd hd;
  ngtcp2_ssize hl;
  size_t off, end;

  memset(w, 0, sizeof(*w));
  hl = pkt_decode_hd_short(&hd, p, n, conn->dcid.current.cid.datalen);
  if (hl < 0) {
    return -1;
  }
  w->dcid_last = hd.dcid.data[hd.dcid.datalen - 1];
  w->pnlen = hd.pkt_numlen;
  end = n - NGTCP2_FAKE_AEAD_OVERHEAD;
  for (off = (size_t)hl; off < end;) {
    ngtcp2_frame fr;
    ngtcp2_frame_decoder frd;
    ngtcp2_ssize r = ngtcp2_frame_decoder_decode(&frd, &fr, p + off, end - off);
    if (r <= 0) {
      return -1;
    }
    off += (size_t)r;
    switch (fr.hd.type) {
    case NGTCP2_FRAME_RETIRE_CONNECTION_ID:
      if (w->nretire < 4) {
        w->retire_seq[w->nretire] = fr.retire_connection_id.seq;
      }
      ++w->nretire;
      break;
    case NGTCP2_FRAME_MAX_DATA:
      w->max_data = fr.max_data.max_data;
      break;
    case NGTCP2_FRAME_MAX_STREAM_DATA:
      w->max_stream_data = fr.max_stream_data.max_stream_data;
      break;
    case NGTCP2_FRAME_STREAMS_BLOCKED_BIDI:
      ++w->nblocked;
      w->blocked_limit = fr.streams_blocked.max_streams;
      break;
    case NGTCP2_FRAME_STREAM:
      if (w->nstreams < 16) {
        w->stream_offsets[w->nstreams] = fr.stream.offset;
        w->stream_lens[w->nstreams] = ngtcp2_vec_len(fr.stream.data, fr.stream.datacnt);
        w->stream_ids[w->nstreams++] = fr.stream.stream_id;
      }
      break;
    }
  }
  return 0;
}

/* ---- 0013: the long header's Length field ---------------------------------------- */

static void test_long_header(void)
{
  static const struct { size_t len; const uint8_t *want; size_t wantlen; } cases[] = {
    { 25, qgo_initial_hdr_25, sizeof(qgo_initial_hdr_25) },
    { 1216, qgo_initial_hdr_1216, sizeof(qgo_initial_hdr_1216) },
    { 1228, qgo_initial_hdr_1228, sizeof(qgo_initial_hdr_1228) },
  };
  size_t i;

  printf("\n0013: the long header, byte for byte with quic-go's ExtendedHeader.Append\n");
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    ngtcp2_pkt_hd hd;
    ngtcp2_cid dcid = { .datalen = 8, .data = { 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 } };
    ngtcp2_cid scid = { 0 };
    uint8_t out[64];
    ngtcp2_ssize n;
    char what[96];

    ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_LONG_FORM, NGTCP2_PKT_INITIAL, &dcid, &scid, 1, 1,
                       NGTCP2_PROTO_VER_V1);
    hd.len = cases[i].len;
    n = ngtcp2_pkt_encode_hd_long(out, sizeof(out), &hd);
    snprintf(what, sizeof(what), "an Initial with Length %zu is quic-go's %zu bytes", cases[i].len,
             cases[i].wantlen);
    ok(n == (ngtcp2_ssize)cases[i].wantlen && memcmp(out, cases[i].want, cases[i].wantlen) == 0,
       what);
  }
}

/* ---- 0006, 0014: the packet-number length --------------------------------------------- */

static void test_pkt_numlen(void)
{
  ngtcp2_conn *conn;
  size_t i, bad = 0;

  printf("\n0006, 0014: the packet-number length, against PacketNumberLengthForHeader[Chrome]\n");

  conn = client_new(1, NULL);
  for (i = 0; i < sizeof(qgo_pn_chrome) / sizeof(qgo_pn_chrome[0]); ++i) {
    conn->pktns.tx.last_pkt_num = qgo_pn_chrome[i].pn - 1;
    conn->pktns.rtb.largest_acked_tx_pkt_num = qgo_pn_chrome[i].largest_acked;
    conn->tx.chrome_last_dgram_padding = 0;
    conn->dcid.current.max_udp_payload_size = 1250;
    conn->cstat.cwnd = (uint64_t)qgo_pn_chrome[i].cwnd_pkts * 1250;
    if (pktns_select_pkt_numlen(conn, &conn->pktns) != qgo_pn_chrome[i].len) {
      printf("        pn %lld, largest acked %lld, cwnd %lld packets: %zu, quic-go %u\n",
             (long long)qgo_pn_chrome[i].pn, (long long)qgo_pn_chrome[i].largest_acked,
             (long long)qgo_pn_chrome[i].cwnd_pkts, pktns_select_pkt_numlen(conn, &conn->pktns),
             qgo_pn_chrome[i].len);
      ++bad;
    }
  }
  ok(bad == 0, "parroting Chrome: every case of quic-go's rule, one, two or four bytes");
  ngtcp2_conn_del(conn);

  conn = client_new(0, NULL);
  bad = 0;
  for (i = 0; i < sizeof(qgo_pn_default) / sizeof(qgo_pn_default[0]); ++i) {
    conn->pktns.tx.last_pkt_num = qgo_pn_default[i].pn - 1;
    conn->pktns.rtb.largest_acked_tx_pkt_num = qgo_pn_default[i].largest_acked;
    if (pktns_select_pkt_numlen(conn, &conn->pktns) != qgo_pn_default[i].len) {
      ++bad;
    }
  }
  ok(bad == 0, "not parroting: every case of quic-go's rule, never one byte");
  ngtcp2_conn_del(conn);
}

/* ---- 0014: the first Initial of a client parroting Chrome ----------------------------- */

static void test_first_initial(void)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn;
  ngtcp2_pkt_hd hd;
  ngtcp2_pkt_info pi = { 0 };
  ngtcp2_ssize n, hl;
  const uint8_t *lenp;

  printf("\n0014: the first Initial of a client parroting Chrome (chrome_parrot.go, transport.go)\n");

  hello_len = 1400; /* too large for one Initial: the parrot splits it */
  conn = client_new(1, NULL);
  n = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof(buf), 1);
  okv(n == 1250, "the datagram is chromeInitialPacketSize", (unsigned long long)n, 1250);
  hl = pkt_decode_hd_long(&hd, buf, (size_t)n);
  ok(hl > 0 && hd.type == NGTCP2_PKT_INITIAL, "and it is an Initial");
  okv(hl > 0 && hd.pkt_num == 1, "numbered 1, as the parrot starts the Initial space",
      (unsigned long long)hd.pkt_num, 1);
  okv(hl > 0 && hd.pkt_numlen == qgo_pn_chrome[1].len,
      "its packet number in one byte: quic-go's rule at pn 1 and a window of 32 datagrams",
      hd.pkt_numlen, qgo_pn_chrome[1].len);
  /* The Length field sits right before the packet number: two bytes, 0b01 prefix. */
  lenp = buf + hl - hd.pkt_numlen - 2;
  ok(hl > 3 && (lenp[0] & 0xc0) == 0x40, "the Length field is a two-byte varint, as quic-go writes it");
  ngtcp2_conn_del(conn);

  hello_len = 217;
  conn = client_new(0, NULL);
  n = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof(buf), 1);
  hl = n > 0 ? pkt_decode_hd_long(&hd, buf, (size_t)n) : -1;
  ok(hl > 0 && hd.pkt_num == 0 && hd.pkt_numlen == qgo_pn_default[0].len,
     "not parroting: the first Initial is numbered 0, in quic-go's two bytes");
  ngtcp2_conn_del(conn);
}

/* ---- 0015: the Destination Connection ID after the handshake -------------------------- */

static void test_dcid(void)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = client_established();
  ngtcp2_frame fr[3];
  size_t i, j, nretired = 0, bad = 0;
  uint64_t retired[8];
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  int64_t sid;

  printf("\n0015: the Destination Connection ID a client uses (conn_id_manager.go)\n");

  /* The server's IDs, highest first in one packet, as quic-go's server lists them. */
  for (i = 0; i < 3; ++i) {
    uint8_t seq = (uint8_t)(3 - i);
    fr[i].new_connection_id = (ngtcp2_new_connection_id){
      .type = NGTCP2_FRAME_NEW_CONNECTION_ID,
      .seq = seq,
      .retire_prior_to = 0,
      .cid = cid_of(seq),
      .token = { .data = { seq } },
    };
  }
  ok(server_sends(conn, fr, 3, ts) == 0, "the three IDs are taken");
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);

  /* Before the handshake completes, no change: QGO_CID_BEFORE_HANDSHAKE. */
  {
    ngtcp2_vec v = { null_data, 100 };
    ngtcp2_pkt_info pi = { 0 };
    written w;
    ngtcp2_ssize n = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, sizeof(buf), NULL,
                                               0, sid, &v, 1, ts);
    ok(n > 0 && parse_short(conn, buf, (size_t)n, &w) == 0 && w.dcid_last == QGO_CID_BEFORE_HANDSHAKE,
       "before the handshake completes the first ID is kept");
  }
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;

  for (i = 0; i < sizeof(qgo_cid_pkts) / sizeof(qgo_cid_pkts[0]); ++i) {
    ngtcp2_vec v = { null_data, 100 };
    ngtcp2_pkt_info pi = { 0 };
    written w;
    ngtcp2_ssize n;

    ts += NGTCP2_MILLISECONDS;
    n = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, sizeof(buf), NULL, 0, sid, &v,
                                  1, ts);
    if (n <= 0 || parse_short(conn, buf, (size_t)n, &w) != 0) {
      ++bad;
      break;
    }
    if (i == 0) {
      conn->dcid.pkts_per_change = 3;
    }
    for (j = 0; j < w.nretire && nretired < 8; ++j) {
      retired[nretired++] = w.retire_seq[j];
    }
    if (w.dcid_last != qgo_cid_pkts[i].seq || nretired != qgo_cid_pkts[i].nretired) {
      printf("        packet %zu: DCID seq %u and %zu retired, quic-go %u and %u\n", i,
             w.dcid_last, nretired, qgo_cid_pkts[i].seq, qgo_cid_pkts[i].nretired);
      ++bad;
    }
  }
  ok(bad == 0, "every packet after it carries the ID quic-go's client would, lowest issued first");
  ok(nretired == sizeof(qgo_cid_retired) &&
       (nretired == 0 || memcmp(retired, (uint64_t[]){ qgo_cid_retired[0], qgo_cid_retired[1] },
                                sizeof(uint64_t) * 2) == 0),
     "and retires the ones it leaves, in quic-go's order");
  ngtcp2_conn_del(conn);
}

/* ---- 0016: the receive windows while a download is read -------------------------------- */

static void test_flow(void)
{
  static uint8_t buf[4096];
  ngtcp2_conn *conn = client_established();
  size_t row = 0, bad = 0;
  int step;
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  uint64_t offset = 0;
  const int nrows = (int)(sizeof(qgo_flow) / sizeof(qgo_flow[0]));

  printf("\n0016: the receive windows, step for step with quic-go's flow controllers\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;

  for (step = 0; step < QGO_FLOW_FAST_STEPS + QGO_FLOW_SLOW_STEPS; ++step) {
    ngtcp2_frame fr;
    ngtcp2_pkt_info pi = { 0 };
    written w;
    ngtcp2_ssize n;
    /* The chunk in STREAM frames of 1 KiB, one to a packet, all at the same instant: a frame
     * cannot carry more than quic-go's packet buffer holds (0033), and the windows see the same
     * bytes arrive either way. */
    ngtcp2_vec data = { null_data, 1024 };
    uint64_t want_s = 0, want_c = 0;
    size_t part;

    ts += step < QGO_FLOW_FAST_STEPS ? QGO_FLOW_FAST_DT_NS : QGO_FLOW_SLOW_DT_NS;
    for (part = 0; part < QGO_FLOW_CHUNK / 1024; ++part) {
      fr.stream = (ngtcp2_stream){
        .type = NGTCP2_FRAME_STREAM,
        .stream_id = 1, /* the server's first bidirectional stream */
        .offset = offset + part * 1024,
        .datacnt = 1,
      };
      fr.stream.data = &data;
      if (server_sends(conn, &fr, 1, ts) != 0) {
        ++bad;
        break;
      }
    }
    if (bad) {
      break;
    }
    offset += QGO_FLOW_CHUNK;
    ngtcp2_conn_extend_max_stream_offset(conn, 1, QGO_FLOW_CHUNK);
    ngtcp2_conn_extend_max_offset(conn, QGO_FLOW_CHUNK);

    /* Everything the client has to send after this step: an ACK, and a window update when one
     * is due. quic-go asks its controllers for updates when it packs a packet, and so it is
     * asked here — the value is what is compared, whichever packet of the step carries it. */
    {
      uint64_t got_s = 0, got_c = 0;
      int k;

      for (k = 0; k < 4; ++k) {
        n = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof(buf), ts);
        if (n <= 0) {
          break;
        }
        if (parse_short(conn, buf, (size_t)n, &w) != 0) {
          ++bad;
          break;
        }
        got_s = w.max_stream_data ? w.max_stream_data : got_s;
        got_c = w.max_data ? w.max_data : got_c;
      }
      w.max_stream_data = got_s;
      w.max_data = got_c;
    }
    if (row < (size_t)nrows && qgo_flow[row].step == step) {
      want_s = qgo_flow[row].max_stream_data;
      want_c = qgo_flow[row].max_data;
      ++row;
    }
    if (w.max_stream_data != want_s || w.max_data != want_c) {
      printf("        step %d: MAX_STREAM_DATA %llu, MAX_DATA %llu; quic-go %llu, %llu\n", step,
             (unsigned long long)w.max_stream_data, (unsigned long long)w.max_data,
             (unsigned long long)want_s, (unsigned long long)want_c);
      if (++bad > 5) {
        break;
      }
    }
  }
  ok(bad == 0, "every window update in the same packet with the same value, growth included");
  ngtcp2_conn_del(conn);
}

/* ---- 0017, 0019: the order lost data is resent in --------------------------------- */

static void test_retransmit_order(void)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = client_established();
  int64_t s0, s4, s8;
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  size_t i, n = sizeof(qgo_lost_order) / sizeof(qgo_lost_order[0]), bad = 0;

  printf("\n0017, 0019: lost data resent in quic-go's order (detectLostPackets, framer.go)\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &s0, NULL);
  ngtcp2_conn_open_bidi_stream(conn, &s4, NULL);
  ngtcp2_conn_open_bidi_stream(conn, &s8, NULL);

  /* The script's seven packets: stream 4 fills the first two, stream 0 the third, four small ones
   * of stream 8 follow; an ACK of the last four declares the first three lost at once. */
  for (i = 0; i < 7; ++i) {
    ts += NGTCP2_MILLISECONDS;
    client_sends(conn, i < 2 ? s4 : i == 2 ? s0 : s8, i < 3 ? 1100 : 10, &ts);
  }
  server_acks(conn, 3, 6, 0, ts + 20 * NGTCP2_MILLISECONDS);

  /* When the first byte of each lost frame goes out again, in order: what goes back to the streams,
   * and the streams in the queue, is in quic-go's order or it is not. How each frame is cut is
   * 0023's, and test_rtxq's. */
  {
    size_t seen = 0, k, j;
    int done[8] = { 0 };

    for (k = 0; k < 8 && seen < n; ++k) {
      ngtcp2_pkt_info pi = { 0 };
      written w;
      ngtcp2_ssize len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200,
                                               ts + 20 * NGTCP2_MILLISECONDS);
      if (len <= 0 || parse_short(conn, buf, (size_t)len, &w) != 0) {
        break;
      }
      for (i = 0; i < w.nstreams; ++i) {
        for (j = 0; j < n; ++j) {
          if (done[j] || w.stream_ids[i] != qgo_lost_order[j].stream_id ||
              qgo_lost_order[j].offset < w.stream_offsets[i] ||
              qgo_lost_order[j].offset >= w.stream_offsets[i] + w.stream_lens[i]) {
            continue;
          }
          if (j != seen) {
            printf("        resent %zu: stream %lld at %llu; quic-go hands back stream %lld at %llu\n",
                   seen, (long long)qgo_lost_order[j].stream_id,
                   (unsigned long long)qgo_lost_order[j].offset,
                   (long long)qgo_lost_order[seen].stream_id,
                   (unsigned long long)qgo_lost_order[seen].offset);
            ++bad;
          }
          done[j] = 1;
          ++seen;
        }
      }
    }
    if (seen != n) {
      printf("        %zu of the %zu lost frames resent\n", seen, n);
      ++bad;
    }
  }
  ok(bad == 0, "one ACK losing three packets: resent oldest loss first, a stream kept at the front "
               "until its losses are out");
  ngtcp2_conn_del(conn);
}

/* ---- 0019: the packet threshold, and no persistent congestion ---------------------- */

static void test_loss_threshold(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS, t1;
  int64_t sid, pn;
  int i;

  printf("\n0019: loss detection as quic-go's (sent_packet_handler.go detectLostPackets)\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);

  pn = client_sends(conn, sid, 100, &ts);
  server_acks(conn, pn, pn, 0, ts + 20 * NGTCP2_MILLISECONDS);
  t1 = ts + 21 * NGTCP2_MILLISECONDS;
  ts = t1;
  for (i = 1; i <= 100; ++i) {
    ts += NGTCP2_MICROSECONDS;
    client_sends(conn, sid, 100, &ts);
  }
  server_acks(conn, pn + 50, pn + 50, 0, t1 + 20 * NGTCP2_MILLISECONDS);
  okv(conn->cstat.pkt_lost == QGO_THRESH_LOST,
      "a hundred out, the fiftieth acknowledged: lost at quic-go's threshold of three",
      conn->cstat.pkt_lost, QGO_THRESH_LOST);
  ngtcp2_conn_del(conn);

  /* Two packets lost 500 ms apart: a window RFC 9002 calls persistent congestion, after which
   * upstream ngtcp2 started its RTT estimate over. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);
  ts = 1000 * NGTCP2_MILLISECONDS;
  pn = client_sends(conn, sid, 100, &ts);
  server_acks(conn, pn, pn, 0, ts + 20 * NGTCP2_MILLISECONDS);
  ts += 30 * NGTCP2_MILLISECONDS;
  t1 = ts;
  client_sends(conn, sid, 100, &ts);
  ts = t1 + 500 * NGTCP2_MILLISECONDS;
  client_sends(conn, sid, 100, &ts);
  ts = t1 + 1000 * NGTCP2_MILLISECONDS;
  client_sends(conn, sid, 100, &ts);
  ts = t1 + 1001 * NGTCP2_MILLISECONDS;
  client_sends(conn, sid, 100, &ts);
  ts = t1 + 1002 * NGTCP2_MILLISECONDS;
  pn = client_sends(conn, sid, 100, &ts);
  server_acks(conn, pn, pn, 0, t1 + 1022 * NGTCP2_MILLISECONDS);
  okv(conn->cstat.smoothed_rtt == QGO_PC_SRTT_NS && conn->cstat.min_rtt == QGO_PC_MIN_NS,
      "a loss window of half a second leaves the RTT estimate as it was", conn->cstat.smoothed_rtt,
      QGO_PC_SRTT_NS);
  ngtcp2_conn_del(conn);
}

/* ---- 0020: the RTT estimate ---------------------------------------------------------- */

static void test_rtt(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  size_t i, n = sizeof(qgo_rtt) / sizeof(qgo_rtt[0]), bad = 0;
  int64_t sid, pn;

  printf("\n0020: the RTT estimate, sample for sample with quic-go's (rtt_stats.go UpdateRTT)\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);

  rtt_unsampled(conn);

  for (i = 0; i < n; ++i) {
    pn = client_sends(conn, sid, 100, &ts);
    ts += (ngtcp2_duration)qgo_rtt[i].rtt;
    server_acks(conn, pn, pn, (ngtcp2_duration)qgo_rtt[i].delay, ts);
    if (conn->cstat.latest_rtt != (ngtcp2_duration)qgo_rtt[i].latest ||
        conn->cstat.min_rtt != (ngtcp2_duration)qgo_rtt[i].min ||
        conn->cstat.smoothed_rtt != (ngtcp2_duration)qgo_rtt[i].smoothed ||
        conn->cstat.rttvar != (ngtcp2_duration)qgo_rtt[i].meandev) {
      printf("        sample %zu (%lld ns, delay %lld): latest %llu min %llu smoothed %llu var %llu; "
             "quic-go %lld %lld %lld %lld\n",
             i, (long long)qgo_rtt[i].rtt, (long long)qgo_rtt[i].delay,
             (unsigned long long)conn->cstat.latest_rtt, (unsigned long long)conn->cstat.min_rtt,
             (unsigned long long)conn->cstat.smoothed_rtt, (unsigned long long)conn->cstat.rttvar,
             (long long)qgo_rtt[i].latest, (long long)qgo_rtt[i].min,
             (long long)qgo_rtt[i].smoothed, (long long)qgo_rtt[i].meandev);
      ++bad;
    }
    ts += NGTCP2_MILLISECONDS;
  }
  ok(bad == 0, "latest, min, smoothed and deviation after every sample, ACK delays capped and not");
  ngtcp2_conn_del(conn);
}

/* ---- 0020: a Retry ------------------------------------------------------------------- */

static void test_retry(void)
{
  static const uint8_t token[] = "retry-token";
  static const ngtcp2_crypto_aead fake_aead;
  static const ngtcp2_duration after[] = { 2 * NGTCP2_MILLISECONDS, 30 * NGTCP2_MILLISECONDS };
  static const int64_t want[] = { QGO_RETRY_SRTT_2MS_NS, QGO_RETRY_SRTT_30MS_NS };
  uint8_t buf[2048];
  ngtcp2_cid scid = cid_of(9);
  size_t i;

  printf("\n0020: a Retry (sent_packet_handler.go ResetForRetry)\n");
  for (i = 0; i < 2; ++i) {
    ngtcp2_conn *conn = client_new(1, NULL);
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize n;
    ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
    char what[128];

    ngtcp2_hybbr_start_reno(&conn->hybbr, &conn->cstat); /* as src/quic/conn.c does */
    ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof(buf), ts);
    n = ngtcp2_pkt_write_retry(buf, sizeof(buf), NGTCP2_PROTO_VER_V1, &conn->oscid, &scid,
                               ngtcp2_conn_get_dcid2(conn), token, sizeof(token) - 1, t_encrypt,
                               &fake_aead, &null_aead_ctx);
    ngtcp2_conn_read_pkt(conn, &test_path.path, &pi, buf, (size_t)n, ts + after[i]);
    snprintf(what, sizeof(what), "a Retry %llu ms after the Initial is an RTT sample of quic-go's",
             (unsigned long long)(after[i] / NGTCP2_MILLISECONDS));
    okv(conn->cstat.smoothed_rtt == (ngtcp2_duration)want[i], what, conn->cstat.smoothed_rtt,
        (unsigned long long)want[i]);
    ok(conn->hybbr.reno.on, "and the controller is kept, NewReno until the authentication");
    ngtcp2_conn_del(conn);
  }
}

/* ---- 0021: the packet numbers left out ------------------------------------------------ */

static void test_skip(void)
{
  static const struct {
    int fill;
    const int64_t *want;
    size_t n;
  } cases[] = {
    { 0x00, qgo_skip_00, sizeof(qgo_skip_00) / sizeof(qgo_skip_00[0]) },
    { 0xff, qgo_skip_ff, sizeof(qgo_skip_ff) / sizeof(qgo_skip_ff[0]) },
  };
  size_t c;

  printf("\n0021: the 1-RTT packet numbers left out (packet_number_generator.go)\n");
  for (c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
    ngtcp2_conn *conn;
    int64_t got[16] = { 0 };
    size_t k = 0, bad = 0;
    char what[128];

    /* The same random bytes quic-go's generator was given, from the first draw, which the
     * connection makes as it is created, to the last. Each turn is what a 1-RTT packet does:
     * leave its number out if it is the one due (conn_handle_skip_pkt), then take the next. */
    rand_fill = cases[c].fill;
    conn = client_new(0, NULL);
    while (k < cases[c].n && conn->pktns.tx.last_pkt_num < cases[c].want[cases[c].n - 1] + 8) {
      int64_t before = conn->pktns.tx.last_pkt_num;

      conn_handle_skip_pkt(conn, &conn->pktns, 1);
      if (conn->pktns.tx.last_pkt_num != before) {
        got[k++] = conn->pktns.tx.last_pkt_num;
      }
      ++conn->pktns.tx.last_pkt_num;
    }
    rand_fill = -1;
    for (k = 0; k < cases[c].n; ++k) {
      if (got[k] != cases[c].want[k]) {
        printf("        skip %zu: %lld, quic-go %lld\n", k, (long long)got[k],
               (long long)cases[c].want[k]);
        ++bad;
      }
    }
    snprintf(what, sizeof(what),
             "random bytes all 0x%02x: the first %zu numbers left out are quic-go's", cases[c].fill,
             cases[c].n);
    ok(bad == 0, what);
    ngtcp2_conn_del(conn);
  }
}

/* ---- 0022: the payload as quic-go lays it out -------------------------------------------- */

/* A 1-RTT packet under construction, as conn_write_pkt begins one. */
static void ppe_start(ngtcp2_conn *conn, ngtcp2_ppe *ppe, ngtcp2_crypto_cc *cc, uint8_t *buf,
                      size_t len)
{
  ngtcp2_pkt_hd hd;

  memset(cc, 0, sizeof(*cc));
  cc->aead = conn->pktns.crypto.ctx.aead;
  cc->hp = conn->pktns.crypto.ctx.hp;
  cc->ckm = conn->pktns.crypto.tx.ckm;
  cc->hp_ctx = conn->pktns.crypto.tx.hp_ctx;
  cc->encrypt = conn->callbacks.encrypt;
  cc->hp_mask = conn->callbacks.hp_mask;
  ngtcp2_ppe_init(ppe, buf, len, 0, cc);
  ngtcp2_pkt_hd_init(&hd, NGTCP2_PKT_FLAG_NONE, NGTCP2_PKT_1RTT, &conn->dcid.current.cid, NULL, 7,
                     2, conn->negotiated_version);
  ngtcp2_ppe_encode_hd(ppe, &hd);
}

/* The frame types of a payload, in order, and the type byte of each in |raw|. */
static size_t payload_types(const uint8_t *p, size_t n, uint64_t *types, uint8_t *raw, size_t cap)
{
  size_t off = 0, k = 0;

  while (off < n && k < cap) {
    ngtcp2_frame fr;
    ngtcp2_frame_decoder frd;
    ngtcp2_ssize r = ngtcp2_frame_decoder_decode(&frd, &fr, p + off, n - off);
    if (r <= 0) {
      return 0;
    }
    raw[k] = p[off];
    types[k++] = fr.hd.type;
    off += (size_t)r;
  }
  return k;
}

/* A client whose first stream has |first| bytes in the packet being built — which leaves |*left| of
 * a packet |*cap| long — and whose second is offered 4000 more. The packet's length when its
 * STREAM frames are two, the first with its Length and the second without and last; -1 when the
 * first is alone, last and so without its Length; -2 for anything else. */
static ngtcp2_ssize two_streams(size_t first, size_t *left, size_t *cap)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  ngtcp2_pkt_info pi = { 0 };
  ngtcp2_ssize nw, taken = -1;
  ngtcp2_vec v = { null_data, first }, big = { null_data, 4000 };
  int64_t s0, s4;
  uint64_t types[32];
  uint8_t raw[32], st[2] = { 0, 0 };
  size_t k = 0, i, ns = 0;

  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &s0, NULL);
  ngtcp2_conn_open_bidi_stream(conn, &s4, NULL);
  nw = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, &taken,
                                 NGTCP2_WRITE_STREAM_FLAG_MORE, s0, &v, 1, ts);
  *left = ngtcp2_ppe_left(&conn->pkt.ppe);
  *cap = ngtcp2_buf_cap(&conn->pkt.ppe.buf);
  nw = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, &taken,
                                 NGTCP2_WRITE_STREAM_FLAG_MORE, s4, &big, 1, ts);
  if (nw == NGTCP2_ERR_WRITE_MORE) {
    nw = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, &taken,
                                   NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ts);
  }
  if (nw > 0) {
    ngtcp2_pkt_hd hd;
    ngtcp2_ssize hl = pkt_decode_hd_short(&hd, buf, (size_t)nw, conn->dcid.current.cid.datalen);
    if (hl > 0) {
      k = payload_types(buf + hl, (size_t)nw - (size_t)hl - NGTCP2_FAKE_AEAD_OVERHEAD, types, raw,
                        32);
    }
  }
  ngtcp2_conn_del(conn);
  for (i = 0; i < k; ++i) {
    if (types[i] == NGTCP2_FRAME_STREAM) {
      if (ns < 2) {
        st[ns] = raw[i];
      }
      ++ns;
    }
  }
  if (k == 0 || types[k - 1] != NGTCP2_FRAME_STREAM) {
    return -2;
  }
  if (ns == 2 && (st[0] & NGTCP2_STREAM_LEN_BIT) && !(st[1] & NGTCP2_STREAM_LEN_BIT)) {
    return nw;
  }
  if (ns == 1 && !(st[0] & NGTCP2_STREAM_LEN_BIT)) {
    return -1;
  }
  return -2;
}

static void test_payload(void)
{
  static uint8_t buf[2048];
  size_t i, bad = 0, n = sizeof(qgo_stream_datalen) / sizeof(qgo_stream_datalen[0]);
  char what[160];

  printf("\n0022: the payload as appendPacketPayload lays it out (packet_packer.go, framer.go)\n");

  /* The data a STREAM frame takes for the room left: quic-go's own numbers. */
  for (i = 0; i < n; ++i) {
    size_t got = conn_lc_stream_max_datalen(qgo_stream_datalen[i].id, qgo_stream_datalen[i].offset,
                                            SIZE_MAX, (size_t)qgo_stream_datalen[i].left);
    if (got != qgo_stream_datalen[i].datalen && bad++ < 5) {
      printf("        stream %lld at %llu, %llu left: %zu bytes, quic-go %llu\n",
             (long long)qgo_stream_datalen[i].id, (unsigned long long)qgo_stream_datalen[i].offset,
             (unsigned long long)qgo_stream_datalen[i].left, got,
             (unsigned long long)qgo_stream_datalen[i].datalen);
    }
  }
  snprintf(what, sizeof(what),
           "a STREAM frame takes what quic-go's popStreamFrame gives it, %zu cases (MaxDataLen)", n);
  ok(bad == 0, what);

  /* The layout: frames given in an order of ngtcp2's — MAX_DATA, the ACK, MAX_STREAM_DATA, a
   * STREAM frame with its Length, a DATAGRAM, a PING — come out ACK first, the four others in an
   * order drawn for each packet, the STREAM frame last and without its Length. Every order of the
   * four equally often: 24000 packets, a chi-square with 23 degrees of freedom. */
  {
    ngtcp2_conn *conn = client_established();
    unsigned counts[24] = { 0 };
    size_t layout_bad = 0, draws = 24000, d;
    double chi = 0;
    static const uint64_t middle[4] = { NGTCP2_FRAME_MAX_DATA, NGTCP2_FRAME_MAX_STREAM_DATA,
                                        NGTCP2_FRAME_DATAGRAM_LEN, NGTCP2_FRAME_PING };
    static uint8_t data[40];
    ngtcp2_vec v = { data, sizeof(data) };

    for (d = 0; d < draws; ++d) {
      ngtcp2_ppe ppe;
      ngtcp2_crypto_cc cc;
      ngtcp2_frame fr;
      ngtcp2_frame_chain *frc;
      size_t acklen, k, perm = 0, used = 0;
      uint64_t types[16];
      uint8_t raw[16];

      ppe_start(conn, &ppe, &cc, buf, 1200);
      fr.max_data = (ngtcp2_max_data){ .type = NGTCP2_FRAME_MAX_DATA, .max_data = 123456 };
      ngtcp2_ppe_encode_frame(&ppe, &fr);
      fr.ack = (ngtcp2_ack){ .type = NGTCP2_FRAME_ACK, .largest_ack = 9, .first_ack_range = 3 };
      ngtcp2_ppe_encode_frame(&ppe, &fr);
      fr.max_stream_data = (ngtcp2_max_stream_data){ .type = NGTCP2_FRAME_MAX_STREAM_DATA,
                                                     .stream_id = 0, .max_stream_data = 65536 };
      ngtcp2_ppe_encode_frame(&ppe, &fr);
      ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &conn->frc_objalloc, conn->mem);
      frc->fr.stream.type = NGTCP2_FRAME_STREAM;
      frc->fr.stream.flags = 0;
      frc->fr.stream.fin = 0;
      frc->fr.stream.stream_id = 4;
      frc->fr.stream.offset = 100;
      frc->fr.stream.datacnt = 1;
      frc->fr.stream.data[0] = v;
      ngtcp2_ppe_encode_frame(&ppe, &frc->fr);
      ngtcp2_frame_chain_objalloc_del(frc, &conn->frc_objalloc, conn->mem);
      fr.datagram = (ngtcp2_datagram){ .type = NGTCP2_FRAME_DATAGRAM_LEN, .datacnt = 1,
                                       .data = &v };
      ngtcp2_ppe_encode_frame(&ppe, &fr);
      fr.ping.type = NGTCP2_FRAME_PING;
      ngtcp2_ppe_encode_frame(&ppe, &fr);

      if (conn_lc_quicgo_payload(conn, &ppe, &acklen) != 0) {
        ++layout_bad;
        continue;
      }
      k = payload_types(buf + ppe.hdlen, ngtcp2_buf_len(&ppe.buf) - ppe.hdlen, types, raw, 16);
      if (k != 6 || types[0] != NGTCP2_FRAME_ACK || types[5] != NGTCP2_FRAME_STREAM ||
          (raw[5] & NGTCP2_STREAM_LEN_BIT) || acklen == 0) {
        if (layout_bad++ < 3) {
          printf("        %zu frames, first 0x%llx, last 0x%02x\n", k,
                 (unsigned long long)(k ? types[0] : 0), k ? raw[k - 1] : 0);
        }
        continue;
      }
      /* The middle four as a permutation, ranked in the factorial base. */
      for (i = 1; i < 5; ++i) {
        size_t j, idx = 0, rank = 0;
        for (j = 0; j < 4; ++j) {
          if (middle[j] == types[i]) {
            idx = j;
          }
        }
        if (used & (1u << idx)) {
          ++layout_bad;
        }
        for (j = 0; j < idx; ++j) {
          rank += !(used & (1u << j));
        }
        used |= 1u << idx;
        perm = perm * (5 - i) + rank;
      }
      ++counts[perm];
    }
    for (i = 0; i < 24; ++i) {
      double e = (double)draws / 24, o = counts[i];
      chi += (o - e) * (o - e) / e;
    }
    ok(layout_bad == 0,
       "ACK first, STREAM last and without its Length, whatever order ngtcp2 wrote them in");
    snprintf(what, sizeof(what),
             "the four others in every order equally often (chi-square %.1f, under 60 with 23 "
             "degrees of freedom)",
             chi);
    ok(layout_bad == 0 && chi < 60, what);
    ngtcp2_conn_del(conn);
  }

  /* A second stream gets a frame while 128 bytes are left and not at 127, and one that has more
   * than the packet holds fills it to the byte, without a Length. */
  {
    size_t left, cap, base;
    ngtcp2_ssize at128, at127;

    two_streams(500, &left, &cap);
    base = 500 + left - 128;
    at128 = two_streams(base, &left, &cap);
    okv(left == 128 && at128 == (ngtcp2_ssize)cap,
        "128 bytes left: the second stream's frame goes in and fills the packet, no Length",
        (unsigned long long)at128, (unsigned long long)cap);
    at127 = two_streams(base + 1, &left, &cap);
    ok(left == 127 && at127 == -1,
       "127 bytes left: no second STREAM frame (MinStreamFrameSize), the first last and without "
       "its Length");
  }

  /* A probe for a larger packet size is a PING and padding: quic-go writes the padding first. */
  {
    ngtcp2_conn *conn = client_established();
    ngtcp2_frame fr;
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize nw;
    size_t hl = 1 + conn->dcid.current.cid.datalen, pl, zeros = 0;

    fr.ping.type = NGTCP2_FRAME_PING;
    nw = ngtcp2_conn_write_single_frame_pkt(
      conn, &pi, buf, 1300, NGTCP2_PKT_1RTT, NGTCP2_WRITE_PKT_FLAG_REQUIRE_PADDING_FULL,
      &conn->dcid.current.cid, &fr, NGTCP2_RTB_ENTRY_FLAG_ACK_ELICITING, NULL,
      1000 * NGTCP2_MILLISECONDS);
    pl = nw > 0 ? (size_t)nw - NGTCP2_FAKE_AEAD_OVERHEAD : 0;
    hl += (size_t)((buf[0] & 0x03u) + 1u);
    for (i = hl; i + 1 < pl; ++i) {
      zeros += buf[i] == 0;
    }
    ok(nw == 1300 && pl > hl && buf[pl - 1] == NGTCP2_FRAME_PING && zeros == pl - 1 - hl,
       "a PMTUD probe: the padding, then the PING");
    ngtcp2_conn_del(conn);
  }
}


/* A client past its handshake whose node takes DATAGRAMs, as hysteria's does. */
static ngtcp2_conn *dgram_client(void)
{
  ngtcp2_conn *conn = client_established();
  conn->remote.transport_params->max_datagram_frame_size = 65535;
  return conn;
}

/* The room an empty 1-RTT packet of this client has for frames: learnt from a packet begun with a
 * one-byte DATAGRAM. */
static size_t empty_room(void)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = dgram_client();
  ngtcp2_pkt_info pi = { 0 };
  uint8_t one = 0;
  ngtcp2_vec v = { &one, 1 };
  int taken = 0;
  size_t room;

  ngtcp2_conn_writev_datagram(conn, &test_path.path, &pi, buf, 1200, &taken,
                              NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &v, 1,
                              1000 * NGTCP2_MILLISECONDS);
  room = ngtcp2_buf_cap(&conn->pkt.ppe.buf) - conn->pkt.ppe.hdlen - NGTCP2_FAKE_AEAD_OVERHEAD;
  ngtcp2_conn_del(conn);
  return room;
}

/* Whether the packet in |buf| of |n| bytes carries a DATAGRAM. */
static int has_datagram(ngtcp2_conn *conn, const uint8_t *buf, ngtcp2_ssize n)
{
  ngtcp2_pkt_hd hd;
  ngtcp2_ssize hl;
  uint64_t types[64];
  uint8_t raw[64];
  size_t k, i;

  if (n <= 0) {
    return 0;
  }
  hl = pkt_decode_hd_short(&hd, buf, (size_t)n, conn->dcid.current.cid.datalen);
  if (hl <= 0) {
    return 0;
  }
  k = payload_types(buf + hl, (size_t)n - (size_t)hl - NGTCP2_FAKE_AEAD_OVERHEAD, types, raw, 64);
  for (i = 0; i < k; ++i) {
    if (types[i] == NGTCP2_FRAME_DATAGRAM_LEN) {
      return 1;
    }
  }
  return 0;
}

static void test_datagram_room(void)
{
  static uint8_t buf[2048], dgram[1500];
  size_t room = empty_room(), i;
  ngtcp2_vec v = { dgram, room - 3 }; /* type and a two-byte length: an empty packet, full */
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;

  printf("\n0022: the DATAGRAM's room (packet_packer.go composeNextPacket)\n");

  /* Seven NEW_CONNECTION_ID frames are queued and no ACK is owed: the DATAGRAM goes first and
   * fills the packet, as quic-go takes it before any control frame. */
  {
    ngtcp2_conn *conn = dgram_client();
    ngtcp2_pkt_info pi = { 0 };
    int taken = 0;
    ngtcp2_ssize nw = ngtcp2_conn_writev_datagram(conn, &test_path.path, &pi, buf, 1200, &taken,
                                                  NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &v, 1, ts);
    if (nw == NGTCP2_ERR_WRITE_MORE) {
      nw = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                     NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ts);
    }
    ok(taken && has_datagram(conn, buf, nw) && conn->pktns.tx.frq != NULL,
       "control frames queued: a DATAGRAM that fills an empty packet goes in, they wait");
    ngtcp2_conn_del(conn);
  }

  /* An ACK is owed: the same DATAGRAM no longer fits, waits for a later packet, and this one goes
   * on — ngtcp2 answers WRITE_MORE. quic-go drops it once its count of passes goes past
   * DatagramFrameMaxPeekTimes, 10, and the count is at one, not nought, after a DATAGRAM has gone
   * out: after the twelve below, the tenth pass is the last. */
  {
    ngtcp2_conn *conn = dgram_client();
    size_t kept = 0, more = 0, dropped_at = 0;

    /* Twelve DATAGRAMs go out first: quic-go's count is back at one after each. */
    for (i = 0; i < 12; ++i) {
      ngtcp2_pkt_info pi = { 0 };
      ngtcp2_vec small = { dgram, 10 };
      int taken = 0;
      ngtcp2_ssize nw;

      ts += NGTCP2_MILLISECONDS;
      nw = ngtcp2_conn_writev_datagram(conn, &test_path.path, &pi, buf, 1200, &taken,
                                       NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &small, 1, ts);
      if (nw == NGTCP2_ERR_WRITE_MORE) {
        ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                  NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ts);
      }
    }
    for (i = 1; i <= 11; ++i) {
      ngtcp2_pkt_info pi = { 0 };
      ngtcp2_frame fr;
      int taken = 0;
      ngtcp2_ssize nw;

      ts += NGTCP2_MILLISECONDS;
      /* Two ack-eliciting packets queue an ACK at once, in quic-go and ngtcp2 alike: a DATAGRAM
       * alone asks only for one already queued. */
      fr.ping.type = NGTCP2_FRAME_PING;
      server_sends(conn, &fr, 1, ts);
      server_sends(conn, &fr, 1, ts);
      nw = ngtcp2_conn_writev_datagram(conn, &test_path.path, &pi, buf, 1200, &taken,
                                       NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &v, 1, ts);
      more += nw == NGTCP2_ERR_WRITE_MORE;
      if (nw == NGTCP2_ERR_WRITE_MORE) {
        nw = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                       NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ts);
      }
      if (has_datagram(conn, buf, nw)) {
        break;
      }
      if (taken) {
        dropped_at = i;
        break;
      }
      ++kept;
    }
    okv(kept == 9 && more == 10 && dropped_at == 10,
        "an ACK owed and no room: passed over, the packet going on each time, dropped at the "
        "tenth pass after a DATAGRAM went out",
        (unsigned long long)dropped_at, 10);
    ngtcp2_conn_del(conn);
  }

  /* One too large even for an empty packet, and no ACK in it: quic-go drops it on the spot — this
   * client never makes one, sizing its datagrams as quic-go does (lc_qudp_fit), but the rule is
   * the reference's. */
  {
    ngtcp2_conn *conn = dgram_client();
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_vec w = { dgram, room };
    int taken = 0;
    ngtcp2_ssize nw;

    while (ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, ts) > 0) {
    }
    nw = ngtcp2_conn_writev_datagram(conn, &test_path.path, &pi, buf, 1200, &taken,
                                     NGTCP2_WRITE_DATAGRAM_FLAG_MORE, 0, &w, 1, ts);
    ok(taken && !has_datagram(conn, buf, nw),
       "no ACK and too large for the packet: taken and dropped, as quic-go drops it");
    ngtcp2_conn_del(conn);
  }

  /* A keep-alive PING alone is too short for the header protection's sample: quic-go puts the
   * padding before the PING, as it does after an ACK. */
  {
    ngtcp2_conn *conn = client_established();
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize nw;
    ngtcp2_pkt_hd hd;
    ngtcp2_ssize hl;
    size_t pl;

    /* A packet from the node starts the keep-alive clock; what it and the handshake left to send
     * goes first. */
    {
      ngtcp2_frame fr;
      fr.ping.type = NGTCP2_FRAME_PING;
      server_sends(conn, &fr, 1, ts);
    }
    ts += 100 * NGTCP2_MILLISECONDS;
    while (ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, ts) > 0) {
    }
    ngtcp2_conn_set_keep_alive_timeout(conn, NGTCP2_MILLISECONDS);
    ts += 10 * NGTCP2_SECONDS;
    nw = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, ts);
    hl = nw > 0 ? pkt_decode_hd_short(&hd, buf, (size_t)nw, conn->dcid.current.cid.datalen) : -1;
    pl = hl > 0 ? (size_t)nw - (size_t)hl - NGTCP2_FAKE_AEAD_OVERHEAD : 0;
    ok(pl >= 2 && buf[hl + (ngtcp2_ssize)pl - 1] == NGTCP2_FRAME_PING && buf[hl] == 0,
       "a keep-alive PING: the padding, then the PING");
    ngtcp2_conn_del(conn);
  }
}


/* ---- 0023: lost STREAM data resent frame by frame ------------------------------------------- */

/* A STREAM frame of stream |sid| at |offset|, |len| bytes, as a lost one goes back to its stream. */
static ngtcp2_frame_chain *lost_frame(ngtcp2_conn *conn, int64_t sid, uint64_t offset, size_t len)
{
  ngtcp2_frame_chain *frc;

  ngtcp2_frame_chain_stream_datacnt_objalloc_new(&frc, 1, &conn->frc_objalloc, conn->mem);
  frc->fr.stream.type = NGTCP2_FRAME_STREAM;
  frc->fr.stream.flags = 0;
  frc->fr.stream.fin = 0;
  frc->fr.stream.stream_id = sid;
  frc->fr.stream.offset = offset;
  frc->fr.stream.datacnt = 1;
  frc->fr.stream.data[0] = (ngtcp2_vec){ null_data, len };
  return frc;
}

static void test_rtxq(void)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = client_established();
  ngtcp2_frame_chain *frc;
  ngtcp2_strm *strm;
  int64_t sid;
  int more;
  size_t i, bad = 0, checked = 0, n = sizeof(qgo_stream_datalen) / sizeof(qgo_stream_datalen[0]);

  printf("\n0023: lost STREAM data resent frame by frame (send_stream.go, framer.go)\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  strm = ngtcp2_conn_find_stream(conn, sid);

  /* In the order they were lost, not by offset: the later bytes first when they were lost first. */
  ngtcp2_strm_streamfrq_push(strm, lost_frame(conn, sid, 500, 500));
  ngtcp2_strm_streamfrq_push(strm, lost_frame(conn, sid, 0, 500));
  ngtcp2_strm_lc_rtxq_pop(strm, &frc, 2000, &more);
  ok(frc && frc->fr.stream.offset == 500 && more,
     "two lost frames: the one lost first goes out first, whatever its offset (retransmissionQueue)");
  if (frc) {
    ngtcp2_frame_chain_objalloc_del(frc, &conn->frc_objalloc, conn->mem);
  }
  ngtcp2_strm_lc_rtxq_pop(strm, &frc, 2000, &more);
  ok(frc && frc->fr.stream.offset == 0 && !more, "then the other, and the queue is empty");
  if (frc) {
    ngtcp2_frame_chain_objalloc_del(frc, &conn->frc_objalloc, conn->mem);
  }

  /* One too large for the room is cut as MaybeSplitOffFrame cuts it, the room being what quic-go
   * asks popRetransmissionFrame with: the room left plus the Length field's length. */
  for (i = 0; i < n; ++i) {
    size_t left = (size_t)qgo_stream_datalen[i].left, want = (size_t)qgo_stream_datalen[i].datalen;
    if (qgo_stream_datalen[i].id != sid || qgo_stream_datalen[i].offset > 16384 || want == 0 ||
        want >= 1400) {
      continue;
    }
    ngtcp2_strm_streamfrq_push(strm, lost_frame(conn, sid, qgo_stream_datalen[i].offset, 1400));
    ngtcp2_strm_lc_rtxq_pop(strm, &frc, left + ngtcp2_put_uvarintlen(left), &more);
    ++checked;
    if (!frc || ngtcp2_vec_len(frc->fr.stream.data, frc->fr.stream.datacnt) != want || !more ||
        strm->tx.lc_rtxq_head->fr.stream.offset != qgo_stream_datalen[i].offset + want) {
      if (bad++ < 3) {
        printf("        at %llu, %zu left: %llu bytes, quic-go %zu\n",
               (unsigned long long)qgo_stream_datalen[i].offset, left,
               frc ? (unsigned long long)ngtcp2_vec_len(frc->fr.stream.data,
                                                        frc->fr.stream.datacnt)
                   : 0ULL,
               want);
      }
    }
    if (frc) {
      ngtcp2_frame_chain_objalloc_del(frc, &conn->frc_objalloc, conn->mem);
    }
    ngtcp2_strm_streamfrq_clear(strm);
  }
  {
    char what[160];
    snprintf(what, sizeof(what),
             "a lost frame too large for the room: cut as quic-go cuts it, %zu cases (MaxDataLen)",
             checked);
    ok(bad == 0 && checked > 50, what);
  }

  /* Not a byte of it fits: nothing is taken, and the queue says it has more. */
  ngtcp2_strm_streamfrq_push(strm, lost_frame(conn, sid, 300, 100));
  ngtcp2_strm_lc_rtxq_pop(strm, &frc, 4, &more);
  ok(frc == NULL && more && strm->tx.lc_rtxq_head != NULL,
     "no room for a byte: nothing taken, the frame kept at the head");
  ngtcp2_strm_streamfrq_clear(strm);
  ngtcp2_conn_del(conn);

  /* Two lost packets whose data meet: resent as the two frames they were, not as one. */
  {
    ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
    int64_t pn[5];
    size_t k;

    conn = client_established();
    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    for (k = 0; k < 5; ++k) {
      ts += NGTCP2_MILLISECONDS;
      pn[k] = client_sends(conn, sid, 300, &ts);
    }
    /* Bytes 0-300 acknowledged before the loss is declared, as another copy of them could be:
     * quic-go resends a lost frame whatever became of its bytes (OnLost). */
    ngtcp2_strm_ack_data(ngtcp2_conn_find_stream(conn, sid), 0, 300);
    server_acks(conn, pn[2], pn[4], 0, ts + 20 * NGTCP2_MILLISECONDS);
    {
      ngtcp2_pkt_info pi = { 0 };
      written w;
      ngtcp2_ssize len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200,
                                               ts + 20 * NGTCP2_MILLISECONDS);
      int got = len > 0 && parse_short(conn, buf, (size_t)len, &w) == 0;
      ok(got && w.nstreams == 2 && w.stream_offsets[0] == 0 && w.stream_lens[0] == 300 &&
           w.stream_offsets[1] == 300 && w.stream_lens[1] == 300,
         "two lost frames that meet: resent as two frames, 0-300 and 300-600, not merged");
    }
    ngtcp2_conn_del(conn);
  }
}


/* A client with nothing of its own left to send and stream |*sid| open, |sent| bytes of it out. */
static ngtcp2_conn *rtx_client(int64_t *sid, uint64_t sent, ngtcp2_tstamp ts)
{
  static uint8_t buf[2048];
  ngtcp2_conn *conn = client_established();
  ngtcp2_pkt_info pi = { 0 };

  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, sid, NULL);
  ngtcp2_conn_find_stream(conn, *sid)->tx.offset = sent;
  while (ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, ts) > 0) {
  }
  return conn;
}

/* Lost frames of |sid| handed back to it, as rtb_reclaim_frame hands them back, and the packet
 * then written; its length, and its STREAM frames in |w|. */
static ngtcp2_ssize rtx_packet(ngtcp2_conn *conn, int64_t sid, const uint64_t *offsets,
                               const size_t *lens, size_t n, written *w, ngtcp2_tstamp ts)
{
  static uint8_t buf[2048];
  ngtcp2_strm *strm = ngtcp2_conn_find_stream(conn, sid);
  ngtcp2_pkt_info pi = { 0 };
  ngtcp2_ssize len;
  size_t i;

  for (i = 0; i < n; ++i) {
    ngtcp2_strm_streamfrq_push(strm, lost_frame(conn, sid, offsets[i], lens[i]));
  }
  strm->cycle = ngtcp2_conn_tx_strmq_first_cycle(conn);
  ngtcp2_conn_tx_strmq_push(conn, strm);
  len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, ts);
  if (len <= 0 || parse_short(conn, buf, (size_t)len, w) != 0) {
    return -1;
  }
  return len;
}

static void test_rtx_room(void)
{
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  ngtcp2_conn *conn;
  int64_t sid;
  written w;
  ngtcp2_ssize full, len;
  size_t room;

  printf("\n0023: the room lost STREAM data is given (framer.go)\n");

  /* A lost frame larger than the packet is cut to fill it to the byte, without a Length: popped
   * with the Length field's length added to the room. */
  {
    uint64_t off = 0;
    size_t big = 3000, left, cap;

    two_streams(500, &left, &cap); /* how long a full packet is */
    conn = rtx_client(&sid, 5000, ts);
    full = rtx_packet(conn, sid, &off, &big, 1, &w, ts);
    room = full > 0 ? (size_t)w.stream_lens[0] + 2 : 0; /* type and stream ID: offset 0, no Length */
    okv(full > 0 && w.nstreams == 1 && full == (ngtcp2_ssize)cap,
        "a lost frame too large for the packet: cut to fill it exactly", (unsigned long long)full,
        (unsigned long long)cap);
    ngtcp2_conn_del(conn);
  }

  /* After a first lost frame, a second gets a piece while 128 bytes are left, and waits at 127. */
  {
    size_t at;
    for (at = 127; at <= 128; ++at) {
      uint64_t offs[2] = { 0, 0 };
      size_t lens[2] = { 0, 500 };

      /* The first frame, at offset 0 with a two-byte Length: 1 + 1 + 2 + its bytes. */
      lens[0] = room - 4 - at;
      offs[1] = lens[0];
      conn = rtx_client(&sid, 5000, ts);
      len = rtx_packet(conn, sid, offs, lens, 2, &w, ts);
      if (at == 128) {
        ok(len > 0 && w.nstreams == 2 && w.stream_offsets[1] == lens[0] && w.stream_lens[1] > 0,
           "128 bytes left after a lost frame: the next lost one gets a piece");
      } else {
        ok(len > 0 && w.nstreams == 1, "127 bytes left: the next lost frame waits");
      }
      ngtcp2_conn_del(conn);
    }
  }
}


/* ---- 0025: STREAMS_BLOCKED at the limit, once per limit --------------------------- */

/* The one rule here held to quic-go's source rather than to a vector from tools/qgovec: it
 * computes nothing — a frame or none, and the limit it carries — so the cited lines are the whole
 * of what a vector would say. */

/* Every STREAMS_BLOCKED the client writes at |ts|, counted into |*n|; the last one's limit. */
static uint64_t blocked_written(ngtcp2_conn *conn, ngtcp2_tstamp ts, size_t *n)
{
  static uint8_t buf[2048];
  uint64_t limit = UINT64_MAX;
  int k;

  *n = 0;
  for (k = 0; k < 4; ++k) {
    ngtcp2_pkt_info pi = { 0 };
    written w;
    ngtcp2_ssize r = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof(buf), ts);
    if (r <= 0 || parse_short(conn, buf, (size_t)r, &w) != 0) {
      break;
    }
    *n += w.nblocked;
    if (w.nblocked) {
      limit = w.blocked_limit;
    }
  }
  return limit;
}

static void test_streams_blocked(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  ngtcp2_frame fr;
  int64_t id;
  size_t n;
  uint64_t limit;
  int opened = 0;

  printf("\n0025: STREAMS_BLOCKED as quic-go's OpenStream sends it\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;

  /* Below the limit nothing is due (streams_map_outgoing.go:76-79 reaches the frame only past it). */
  ngtcp2_conn_lc_streams_blocked_bidi(conn);
  blocked_written(conn, ts, &n);
  okv(n == 0, "no frame while streams are left", n, 0);

  while (ngtcp2_conn_open_bidi_stream(conn, &id, NULL) == 0) {
    ++opened;
  }
  okv(opened == 100, "the node's limit is reached", (unsigned long long)opened, 100);

  /* At it: one frame carrying the limit, and a second refusal at the same limit sends none
   * (blockedSent, :144-160). */
  ngtcp2_conn_lc_streams_blocked_bidi(conn);
  ngtcp2_conn_lc_streams_blocked_bidi(conn);
  limit = blocked_written(conn, ts, &n);
  okv(n == 1 && limit == 100, "one frame, carrying the limit", n == 1 ? limit : n, 100);
  ngtcp2_conn_lc_streams_blocked_bidi(conn);
  blocked_written(conn, ts, &n);
  okv(n == 0, "not again at the same limit", n, 0);

  /* A MAX_STREAMS that raises it re-arms the frame (SetMaxStream, :189-197). */
  fr.max_streams = (ngtcp2_max_streams){ .type = NGTCP2_FRAME_MAX_STREAMS_BIDI, .max_streams = 101 };
  server_sends(conn, &fr, 1, ts);
  ngtcp2_conn_open_bidi_stream(conn, &id, NULL);
  ngtcp2_conn_lc_streams_blocked_bidi(conn);
  limit = blocked_written(conn, ts, &n);
  okv(n == 1 && limit == 101, "again at the raised limit", n == 1 ? limit : n, 101);

  ngtcp2_conn_del(conn);
}

/* ---- 0026: the key update quic-go initiates ------------------------------------------ */

/* The key phase bit of the packet the client writes next, 0 or 1; -1 when it writes none. The
 * null header protection masks nothing, so the bit is readable as it stands. */
static int next_key_phase(ngtcp2_conn *conn, ngtcp2_tstamp *ts)
{
  static uint8_t buf[2048];
  ngtcp2_vec v = { null_data, 10 };
  int i;

  for (i = 0; i < 100000; ++i, *ts += NGTCP2_MICROSECONDS) {
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize n = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                               NGTCP2_WRITE_STREAM_FLAG_NONE, 0, &v, 1, *ts);
    if (n > 0) {
      return (buf[0] & NGTCP2_SHORT_KEY_PHASE_BIT) != 0;
    }
  }
  return -1;
}

static void test_key_update(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  int64_t sid = -1;
  int k, phase100 = -2, phase101 = -2, later = 0;

  printf("\n0026: the key update quic-go initiates\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);

  /* FirstKeyUpdateInterval: the hundredth packet goes with the first keys, the next with new ones
   * (vendor/quic-go/internal/handshake/updatable_aead.go:318-356). */
  for (k = 1; k <= 101; ++k) {
    int p = next_key_phase(conn, &ts);
    if (k == 100) {
      phase100 = p;
    }
    if (k == 101) {
      phase101 = p;
    }
  }
  okv(phase100 == 0, "the hundredth packet sent keeps the first keys", (unsigned long long)phase100, 0);
  okv(phase101 == 1, "the one after it goes out with the next", (unsigned long long)phase101, 1);

  /* And then no other for a hundred thousand: with everything acknowledged — which is what allows
   * the next one (updateAllowed, :306-316) — a hundred and fifty more stay in phase one. */
  server_acks(conn, 0, conn->pktns.tx.last_pkt_num, 0, ts);
  ts += 2 * NGTCP2_SECONDS; /* past a PTO, when ngtcp2 has the next keys ready */
  for (k = 0; k < 150; ++k) {
    later |= next_key_phase(conn, &ts) != 1;
  }
  okv(later == 0, "the next update waits for the long interval", (unsigned long long)later, 0);
  ngtcp2_conn_del(conn);

  /* The same count of packets OPENED: a hundred from the server, and the client's next packet is
   * the first with new keys. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  (void)next_key_phase(conn, &ts); /* keys for the next phase are prepared on a write */
  for (k = 0; k < 100; ++k) {
    ngtcp2_frame fr;
    fr.hd.type = NGTCP2_FRAME_PING;
    server_sends(conn, &fr, 1, ts);
  }
  {
    int p = next_key_phase(conn, &ts);
    okv(p == 1, "a hundred packets opened do the same", (unsigned long long)p, 1);
  }
  ngtcp2_conn_del(conn);
}

/* ---- 0027: the close a client sends mid-handshake ------------------------------------ */

static void test_close_mid_handshake(int application_keys)
{
  static uint8_t buf[2048], dg[2048];
  ngtcp2_conn *conn = client_new(0, NULL);
  ngtcp2_pkt_info pi = { 0 };
  ngtcp2_ccerr ccerr;
  ngtcp2_ssize n;
  size_t dgramlen, off, len0 = 0;
  int types_ok = 0, pad_first = 0, cc_last = 0, count = 0;

  printf("\n0027: a client's CONNECTION_CLOSE during the handshake\n");

  /* The first Initial, which moves the client past CLIENT_INITIAL; then the Handshake keys a
   * ServerHello would have brought. The Initial keys are still held. */
  n = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof buf, 0);
  ngtcp2_conn_set_crypto_ctx(conn, &fake_crypto_ctx);
  ngtcp2_conn_install_rx_handshake_key(conn, &null_aead_ctx, null_iv, sizeof(null_iv),
                                       &null_hp_ctx);
  ngtcp2_conn_install_tx_handshake_key(conn, &null_aead_ctx, null_iv, sizeof(null_iv),
                                       &null_hp_ctx);
  conn->negotiated_version = conn->client_chosen_version; /* as the ServerHello's Initial sets it */
  if (application_keys) {
    ngtcp2_conn_install_tx_key(conn, null_secret, sizeof(null_secret), &null_aead_ctx, null_iv,
                              sizeof(null_iv), &null_hp_ctx);
    conn->state = NGTCP2_CS_POST_HANDSHAKE;
  }

  ngtcp2_ccerr_set_tls_alert(&ccerr, 42, NULL, 0); /* bad_certificate */
  n = ngtcp2_conn_write_connection_close(conn, &test_path.path, &pi, dg, sizeof dg, &ccerr, 1);
  dgramlen = ngtcp2_min(conn->local.settings.max_tx_udp_payload_size,
                        conn->dcid.current.max_udp_payload_size);

  /* quic-go a10df75c counts the short-header AEAD overhead too (packet_packer.go::
   * packConnectionClose). Initial + Handshake + 1-RTT must still fit maxPacketSize. */
  for (off = 0; n > 0 && off < (size_t)n && count < 4; ++count) {
    if ((dg[off] & 0x80u) == 0) {
      types_ok = types_ok && application_keys && count == 2 && (dg[off] & 0x40u) != 0;
      ++count;
      off = (size_t)n;
      break;
    }
    ngtcp2_pkt_hd hd;
    ngtcp2_ssize hl = ngtcp2_pkt_decode_hd_long(&hd, dg + off, (size_t)n - off);
    size_t plen;
    if (hl < 0) {
      break;
    }
    plen = (size_t)hl + hd.len - hd.pkt_numlen;
    if (count == 0) {
      types_ok = hd.type == NGTCP2_PKT_INITIAL;
      len0 = plen;
      /* Null crypto leaves the payload readable: padding (zeros) first, the frame (0x1c) last. */
      /* Past the packet number, whose length null header protection leaves in the first byte. */
      size_t body = (size_t)hl + (size_t)(dg[off] & 0x03u) + 1u;
      pad_first = dg[off + body] == 0x00u;
      for (size_t k = body; k < plen - NGTCP2_INITIAL_AEAD_OVERHEAD; ++k) {
        if (dg[off + k] == 0x1cu) {
          cc_last = 1;
          break;
        }
        if (dg[off + k] != 0x00u) {
          break;
        }
      }
    } else if (count == 1) {
      types_ok = types_ok && hd.type == NGTCP2_PKT_HANDSHAKE;
    }
    off += plen;
  }
  okv(n > 0 && (size_t)n == dgramlen, "one datagram, exactly maxPacketSize",
      (unsigned long long)n, (unsigned long long)dgramlen);
  int expected = application_keys ? 3 : 2;
  okv(count == expected && types_ok, "Initial, Handshake, and 1-RTT only when its keys exist",
      (unsigned long long)count, (unsigned long long)expected);
  ok(pad_first && cc_last && len0 > 0, "the Initial's padding comes before its frame");
  ngtcp2_conn_del(conn);
}

/* ---- 0028: the handshake confirmed by an ACK of a 1-RTT packet ------------------------ */

static void test_confirm_on_ack(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  int64_t sid = -1, pn;
  int before;

  printf("\n0028: an ACK of a 1-RTT packet confirms the handshake, as quic-go takes it\n");
  /* Complete but not yet confirmed: HANDSHAKE_DONE has not arrived. */
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  conn->flags &= ~(uint32_t)NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  pn = client_sends(conn, sid, 100, &ts);
  before = (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED) != 0;
  server_acks(conn, pn, pn, 0, ts + 20 * NGTCP2_MILLISECONDS);
  ok(!before && (conn->flags & NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED) != 0,
     "not confirmed before the ACK, confirmed by it");
  ngtcp2_conn_del(conn);
}

/* ---- 0029: up to 64 ACK ranges --------------------------------------------------------- */

static void test_ack_ranges(void)
{
  static uint8_t buf[4096];
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  ngtcp2_pkt_info pi = { 0 };
  ngtcp2_ssize n;
  size_t ranges = 0;
  int k;

  printf("\n0029: an ACK carries up to 64 ranges, as quic-go's history keeps them\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  /* Seventy ack-eliciting packets with a gap before each: seventy ranges received. */
  for (k = 0; k < 70; ++k) {
    ngtcp2_frame fr;
    fr.hd.type = NGTCP2_FRAME_PING;
    server_last_pn += 1;
    server_sends(conn, &fr, 1, ts);
  }
  n = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, sizeof buf, ts + NGTCP2_SECONDS);
  if (n > 0) {
    ngtcp2_pkt_hd hd;
    ngtcp2_ssize hl = pkt_decode_hd_short(&hd, buf, (size_t)n, conn->dcid.current.cid.datalen);
    size_t off = hl > 0 ? (size_t)hl : (size_t)n, end = (size_t)n - NGTCP2_FAKE_AEAD_OVERHEAD;
    while (off < end) {
      ngtcp2_frame fr;
      ngtcp2_frame_decoder frd;
      ngtcp2_ssize r = ngtcp2_frame_decoder_decode(&frd, &fr, buf + off, end - off);
      if (r <= 0) {
        break;
      }
      if (fr.hd.type == NGTCP2_FRAME_ACK) {
        ranges = fr.ack.rangecnt + 1;
      }
      off += (size_t)r;
    }
  }
  okv(ranges == 64, "seventy ranges received, sixty-four acknowledged", (unsigned long long)ranges,
      64);
  ngtcp2_conn_del(conn);
}

/* ---- 0030: ECN as quic-go's ecnTracker ------------------------------------------------ */

/* The state names qgo_ecn gives, ecnStateInitial folded into "testing" as the patch folds it. */
static const char *ecn_state_name(ngtcp2_ecn_state s)
{
  switch (s) {
  case NGTCP2_ECN_STATE_TESTING:
    return "testing";
  case NGTCP2_ECN_STATE_UNKNOWN:
    return "unknown";
  case NGTCP2_ECN_STATE_CAPABLE:
    return "capable";
  default:
    return "failed";
  }
}

/* Every script of tools/qgovec's qgoECNScripts replayed on the connection, word for word: the
 * marking each datagram went out with, and the tracker's verdict at the end, against what quic-go's
 * sentPacketHandler did with the same packets and the same acknowledgements. */
static void test_ecn(void)
{
  size_t i, n = sizeof(qgo_ecn) / sizeof(qgo_ecn[0]);

  printf("\n0030: ECN marked and validated as quic-go's ecnTracker does (ecn.go)\n");
  for (i = 0; i < n; ++i) {
    ngtcp2_conn *conn = client_established();
    ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
    static uint8_t buf[2048];
    int64_t sid, pns[64];
    size_t np = 0, nm = 0;
    char marks[64], what[160];
    const char *p = qgo_ecn[i].script;
    int broken = 0;

    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    rtt_unsampled(conn);

    while (*p && !broken) {
      char *end;
      long k, count;

      while (*p == ' ') {
        ++p;
      }
      switch (*p) {
      case 'S':
        count = strtol(p + 1, &end, 10);
        p = end;
        for (k = 0; k < count && np < 64; ++k) {
          ngtcp2_vec v = { null_data, 100 };
          ngtcp2_ssize w = 0;
          ngtcp2_pkt_info pi = { 0 };
          int t;

          for (t = 0; t < 100000 && w <= 0; ++t, ts += NGTCP2_MICROSECONDS) {
            memset(&pi, 0, sizeof(pi));
            w = ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                          NGTCP2_WRITE_STREAM_FLAG_NONE, sid, &v, 1, ts);
          }
          if (w <= 0) {
            broken = 1;
            break;
          }
          pns[np++] = conn->pktns.tx.last_pkt_num;
          marks[nm++] = pi.ecn == NGTCP2_ECN_ECT_0 ? 'E' : 'N';
          ts += NGTCP2_MILLISECONDS;
        }
        break;
      case 'K':
      case 'k': {
        /* Two PINGs from the server make an acknowledgement due at once, and it goes out in a
         * packet of its own — K through the writer the paced loop uses (patch 0010), k through
         * ngtcp2_conn_writev_stream with no stream, the two ways an ACK-only packet leaves. */
        ngtcp2_frame fr;
        ngtcp2_pkt_info pi = { 0 };
        ngtcp2_ssize w;
        char op = *p++;

        fr.ping.type = NGTCP2_FRAME_PING;
        server_sends(conn, &fr, 1, ts);
        server_sends(conn, &fr, 1, ts);
        w = op == 'K' ? ngtcp2_conn_write_ack_pkt_1rtt(conn, &pi, buf, 1200, ts)
                      : ngtcp2_conn_writev_stream(conn, &test_path.path, &pi, buf, 1200, NULL,
                                                  NGTCP2_WRITE_STREAM_FLAG_NONE, -1, NULL, 0, ts);
        if (w <= 0 || np == 64) {
          broken = 1;
          break;
        }
        pns[np++] = conn->pktns.tx.last_pkt_num;
        marks[nm++] = pi.ecn == NGTCP2_ECN_ECT_0 ? 'E' : 'N';
        ts += NGTCP2_MILLISECONDS;
        break;
      }
      case 'T':
        ts += (ngtcp2_tstamp)strtol(p + 1, &end, 10) * NGTCP2_MILLISECONDS;
        p = end;
        break;
      case 'A': {
        long lo, hi;
        unsigned long long ect0 = 0, ect1 = 0, ce = 0;
        int with_counts = 0;
        ngtcp2_frame fr;

        lo = strtol(p + 1, &end, 10);
        hi = strtol(end + 1, &end, 10);
        p = end;
        if (*p == ':') {
          with_counts = 1;
          ect0 = strtoull(p + 1, &end, 10);
          ect1 = strtoull(end + 1, &end, 10);
          ce = strtoull(end + 1, &end, 10);
          p = end;
        }
        if (lo < 0 || hi < lo || (size_t)hi >= np) {
          broken = 1;
          break;
        }
        ts += 19 * NGTCP2_MILLISECONDS;
        memset(&fr, 0, sizeof(fr));
        fr.ack.type = with_counts ? NGTCP2_FRAME_ACK_ECN : NGTCP2_FRAME_ACK;
        fr.ack.largest_ack = pns[hi];
        fr.ack.first_ack_range = (uint64_t)(pns[hi] - pns[lo]);
        fr.ack.ecn.ect0 = ect0;
        fr.ack.ecn.ect1 = ect1;
        fr.ack.ecn.ce = ce;
        server_sends(conn, &fr, 1, ts);
        ts += NGTCP2_MILLISECONDS;
        break;
      }
      default:
        broken = 1;
      }
    }
    marks[nm] = '\0';

    snprintf(what, sizeof(what), "%s: marked %s, %s", qgo_ecn[i].script, qgo_ecn[i].marks,
             qgo_ecn[i].state);
    if (broken || strcmp(marks, qgo_ecn[i].marks) != 0 ||
        strcmp(ecn_state_name(conn->tx.ecn.state), qgo_ecn[i].state) != 0) {
      printf("        got %s, %s%s\n", marks, ecn_state_name(conn->tx.ecn.state),
             broken ? " (the script could not be played)" : "");
      ok(0, what);
    } else {
      ok(1, what);
    }
    ngtcp2_conn_del(conn);
  }

  /* Two rules the tracker never sees, so qgo_ecn cannot carry them: they are the connection's, read
   * off vendor/quic-go/connection.go. Before the handshake is confirmed, an ACK-only datagram is
   * written with ECNMode(false), Not-ECT (:2705-2707). A CONNECTION_CLOSE takes ECNMode like any
   * packet and is never registered with the tracker (:2895-2897). */
  {
    ngtcp2_conn *conn = client_established();
    ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
    static uint8_t buf[2048];
    ngtcp2_frame fr;
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize w;
    ngtcp2_ccerr ccerr;
    int64_t sid;
    uint64_t sent;

    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    conn->flags &= (uint32_t)~NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
    fr.ping.type = NGTCP2_FRAME_PING;
    server_sends(conn, &fr, 1, ts);
    server_sends(conn, &fr, 1, ts);
    w = ngtcp2_conn_write_ack_pkt_1rtt(conn, &pi, buf, 1200, ts);
    ok(w > 0 && pi.ecn == NGTCP2_ECN_NOT_ECT && conn->tx.ecn.num_sent_ect0 == 0,
       "an ACK-only datagram before the handshake is confirmed: Not-ECT, and not a testing packet");

    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    client_sends(conn, sid, 100, &ts);
    sent = conn->tx.ecn.num_sent_ect0;
    ngtcp2_ccerr_set_application_error(&ccerr, 0x100, NULL, 0);
    memset(&pi, 0, sizeof(pi));
    w = ngtcp2_conn_write_connection_close(conn, &test_path.path, &pi, buf, 1200, &ccerr, ts);
    ok(w > 0 && pi.ecn == NGTCP2_ECN_ECT_0 && conn->tx.ecn.num_sent_ect0 == sent,
       "a CONNECTION_CLOSE while testing: marked ECT(0), and not counted");
    ngtcp2_conn_del(conn);
  }
}

/* ---- 0031: an ACK over quic-go's history --------------------------------------------- */

/* An ACK-only packet from the client, after two PINGs from the server have made one due at once. */
static int64_t client_acks_only(ngtcp2_conn *conn, ngtcp2_tstamp ts)
{
  static uint8_t buf[2048];
  ngtcp2_frame fr;
  ngtcp2_pkt_info pi = { 0 };

  fr.ping.type = NGTCP2_FRAME_PING;
  server_sends(conn, &fr, 1, ts);
  server_sends(conn, &fr, 1, ts);
  if (ngtcp2_conn_write_ack_pkt_1rtt(conn, &pi, buf, 1200, ts) <= 0) {
    return -1;
  }
  return conn->pktns.tx.last_pkt_num;
}

/* One stream packet written at exactly |ts|, the pacer out of the way: the scripts here are timed to
 * the millisecond, as quic-go's are. */
static int64_t client_sends_at(ngtcp2_conn *conn, int64_t sid, ngtcp2_tstamp ts)
{
  ngtcp2_tstamp at = ts;

  conn->tx.pacing.next_ts = UINT64_MAX;
  return client_sends(conn, sid, 100, &at);
}

static void test_history(void)
{
  ngtcp2_conn *conn;
  ngtcp2_tstamp t0 = 1000 * NGTCP2_MILLISECONDS;
  int64_t sid, pn[4];
  int i, bad;

  printf("\n0031: an ACK is taken over what quic-go's history holds (sent_packet_handler.go "
         "ReceivedAck)\n");

  /* Packet 0 carries data, 1-3 are ACK-only; an ACK of 1-3 has acknowledged something, and loss
   * detection runs on it: packet 0 is three behind. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);
  pn[0] = client_sends_at(conn, sid, t0);
  bad = pn[0] < 0;
  for (i = 1; i <= 3; ++i) {
    pn[i] = client_acks_only(conn, t0 + (ngtcp2_tstamp)i * NGTCP2_MILLISECONDS);
    bad |= pn[i] != pn[i - 1] + 1;
  }
  server_acks(conn, pn[1], pn[3], 0, t0 + 23 * NGTCP2_MILLISECONDS);
  okv(!bad && conn->cstat.pkt_lost == QGO_HIST_ACKONLY_LOST,
      "an ACK of three ACK-only packets looks for losses: the data packet before them is lost",
      conn->cstat.pkt_lost, QGO_HIST_ACKONLY_LOST);
  ngtcp2_conn_del(conn);

  /* Data packets 0-3; an ACK of 1-3 loses packet 0, and an ACK of 0 after that acknowledges
   * nothing — the packet left quic-go's history when it was lost. Its data goes out again. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);
  bad = 0;
  for (i = 0; i <= 3; ++i) {
    pn[i] = client_sends_at(conn, sid, t0 + (ngtcp2_tstamp)i * NGTCP2_MILLISECONDS);
    bad |= i > 0 && pn[i] != pn[i - 1] + 1;
  }
  server_acks(conn, pn[1], pn[3], 0, t0 + 23 * NGTCP2_MILLISECONDS);
  okv(!bad && conn->cstat.pkt_lost == QGO_HIST_LATE_LOST, "an ACK of 1-3 loses packet 0",
      conn->cstat.pkt_lost, QGO_HIST_LATE_LOST);
  server_acks(conn, pn[0], pn[0], 0, t0 + 24 * NGTCP2_MILLISECONDS);
  {
    static uint8_t buf[2048];
    ngtcp2_pkt_info pi = { 0 };
    written w;
    size_t k;
    int resent = 0;
    ngtcp2_ssize len;

    conn->tx.pacing.next_ts = UINT64_MAX;
    len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200,
                                t0 + 24 * NGTCP2_MILLISECONDS);
    if (len > 0 && parse_short(conn, buf, (size_t)len, &w) == 0) {
      for (k = 0; k < w.nstreams; ++k) {
        resent |= w.stream_ids[k] == sid && w.stream_offsets[k] == 0;
      }
    }
    ok(QGO_HIST_LATE_ACKED == 0 && resent,
       "an ACK of packet 0 after it was lost acknowledges nothing: its data is sent again");
  }
  ngtcp2_conn_del(conn);

  /* Packet 0 carries data, packet 1 is ACK-only; an ACK of both, its largest the ACK-only one, is
   * an RTT sample from that packet. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);
  pn[0] = client_sends_at(conn, sid, t0);
  pn[1] = client_acks_only(conn, t0 + NGTCP2_MILLISECONDS);
  server_acks(conn, pn[0], pn[1], 0, t0 + 21 * NGTCP2_MILLISECONDS);
  okv(pn[1] == pn[0] + 1 && conn->cstat.smoothed_rtt == (ngtcp2_duration)QGO_HIST_NAE_SRTT_NS,
      "an ACK whose largest is an ACK-only packet: an RTT sample from it", conn->cstat.smoothed_rtt,
      (unsigned long long)QGO_HIST_NAE_SRTT_NS);
  ngtcp2_conn_del(conn);

  /* Data 0 acknowledged; ACK-only 1, data 2 and — the first time — data 3; an ACK of 2 alone
   * leaves 1 neither acknowledged nor lost. With 3 outstanding the loss timer is 1's; with nothing
   * outstanding quic-go has no timer at all, loss time or not. */
  for (i = 0; i < 2; ++i) {
    long long want = i == 0 ? QGO_HIST_LOSS_TIMER_NS : QGO_HIST_NO_TIMER_NS;
    long long got;

    conn = client_established();
    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    rtt_unsampled(conn);
    pn[0] = client_sends_at(conn, sid, t0);
    server_acks(conn, pn[0], pn[0], 0, t0 + 20 * NGTCP2_MILLISECONDS);
    pn[1] = client_acks_only(conn, t0 + 21 * NGTCP2_MILLISECONDS);
    pn[2] = client_sends_at(conn, sid, t0 + 22 * NGTCP2_MILLISECONDS);
    if (i == 0) {
      client_sends_at(conn, sid, t0 + 23 * NGTCP2_MILLISECONDS);
    }
    server_acks(conn, pn[2], pn[2], 0, t0 + 42 * NGTCP2_MILLISECONDS);
    got = conn->cstat.loss_detection_timer == UINT64_MAX
            ? -1
            : (long long)(conn->cstat.loss_detection_timer - t0);
    printf("        loss detection timer %lld ns from the start, quic-go's %lld\n", got, want);
    ok(pn[1] == pn[0] + 1 && pn[2] == pn[1] + 1 && got == want,
       i == 0 ? "an ACK-only packet left behind the largest acknowledged sets the loss timer"
              : "nothing outstanding: no timer, though an ACK-only packet has a loss time");
    ngtcp2_conn_del(conn);
  }

  /* Data 0 and 1; an ACK of 1, then a late one of 0: packet 0 was sent before the one last
   * sampled, and quic-go takes no sample from it (largestAckedTime). */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);
  pn[0] = client_sends_at(conn, sid, t0);
  pn[1] = client_sends_at(conn, sid, t0 + NGTCP2_MILLISECONDS);
  server_acks(conn, pn[1], pn[1], 0, t0 + 21 * NGTCP2_MILLISECONDS);
  server_acks(conn, pn[0], pn[0], 0, t0 + 41 * NGTCP2_MILLISECONDS);
  okv(pn[1] == pn[0] + 1 && conn->cstat.smoothed_rtt == (ngtcp2_duration)QGO_HIST_LATE_SRTT_NS,
      "a late ACK of a packet sent before the last one sampled: no RTT sample",
      conn->cstat.smoothed_rtt, (unsigned long long)QGO_HIST_LATE_SRTT_NS);
  ngtcp2_conn_del(conn);

  /* The history holds every packet number space's ACK-only packets, the Handshake space's too
   * (sent_packet_handler.go:331 registers every packet, whatever its level). */
  {
    static uint8_t buf[2048];
    ngtcp2_frame fr;
    ngtcp2_tpe tpe;
    ngtcp2_pkt_info pi = { 0 };
    size_t n;
    ngtcp2_ssize len;

    conn = client_established();
    conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
    conn->flags &= (uint32_t)~NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED;
    fr.ping.type = NGTCP2_FRAME_PING;
    ngtcp2_tpe_init_conn(&tpe, conn);
    n = ngtcp2_tpe_write_handshake(&tpe, buf, sizeof(buf), &fr, 1);
    ngtcp2_conn_read_pkt(conn, &test_path.path, &pi, buf, n, t0);
    conn->tx.pacing.next_ts = UINT64_MAX;
    len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200,
                                t0 + 30 * NGTCP2_MILLISECONDS);
    ok(len > 0 && conn->hs_pktns != NULL && conn->hs_pktns->tx.nae_len == 1,
       "a Handshake packet carrying only an ACK is kept in the history, as a 1-RTT one is");
    ngtcp2_conn_del(conn);
  }
}

/* ---- 0032: what a PTO probe carries --------------------------------------------------- */

static void test_probe(void)
{
  ngtcp2_conn *conn = client_established();
  ngtcp2_tstamp t0 = 1000 * NGTCP2_MILLISECONDS, at;
  static uint8_t buf[2048];
  int64_t sid, pn0, last = -1;
  written w[2];
  int64_t probe_pn[2] = { -1, -1 };
  int i, bad = 0;

  printf("\n0032: a PTO probe as quic-go packs one (QueueProbePacket, connection.go "
         "sendProbePacket)\n");
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
  rtt_unsampled(conn);

  pn0 = client_sends_at(conn, sid, t0);
  server_acks(conn, pn0, pn0, 0, t0 + 20 * NGTCP2_MILLISECONDS);
  for (i = 0; i < 3; ++i) {
    last = client_sends_at(conn, sid, t0 + (ngtcp2_tstamp)(21 + i) * NGTCP2_MILLISECONDS);
  }

  at = conn->cstat.loss_detection_timer;
  okv(at - t0 == (ngtcp2_tstamp)QGO_PTO_AT_NS, "the PTO fires when quic-go's does", at - t0,
      (unsigned long long)QGO_PTO_AT_NS);
  ngtcp2_conn_on_loss_detection_timer(conn, at);
  okv(conn->pktns.rtb.probe_pkt_left == 2 && QGO_PTO_APPDATA,
      "two 1-RTT probes owed", conn->pktns.rtb.probe_pkt_left, 2);

  for (i = 0; i < 2; ++i) {
    ngtcp2_pkt_info pi = { 0 };
    ngtcp2_ssize len;

    conn->tx.pacing.next_ts = UINT64_MAX;
    len = ngtcp2_conn_write_pkt(conn, &test_path.path, &pi, buf, 1200, at);
    if (len <= 0 || parse_short(conn, buf, (size_t)len, &w[i]) != 0) {
      bad = 1;
      break;
    }
    probe_pn[i] = conn->pktns.tx.last_pkt_num;
  }

  okv(!bad && probe_pn[0] - last == QGO_PTO_PN_GAP,
      "the first probe is numbered past a number left out, as quic-go's", (unsigned long long)(probe_pn[0] - last),
      QGO_PTO_PN_GAP);
  for (i = 0; i < 2 && !bad; ++i) {
    size_t k;
    int found = 0;

    for (k = 0; k < w[i].nstreams; ++k) {
      found |= w[i].stream_ids[k] == sid && w[i].stream_offsets[k] == qgo_pto_requeued[i];
    }
    printf("        probe %d: %zu stream frame(s), the first at offset %llu; quic-go resends %llu\n",
           i + 1, w[i].nstreams, w[i].nstreams ? (unsigned long long)w[i].stream_offsets[0] : 0ull,
           (unsigned long long)qgo_pto_requeued[i]);
    bad |= !found;
  }
  ok(!bad, "each probe carries what the oldest outstanding packet carried, oldest first");
  okv(conn->cstat.pkt_lost == 0, "and nothing is counted as lost: the probe declares no loss",
      conn->cstat.pkt_lost, 0);

  /* The first packet the probes took is acknowledged after all. It left quic-go's history when it
   * was taken, so the ACK acknowledges nothing, and the largest acknowledged does not move. */
  server_acks(conn, pn0 + 1, pn0 + 1, 0, at + 10 * NGTCP2_MILLISECONDS);
  okv(conn->pktns.rtb.largest_acked_tx_pkt_num - pn0 == QGO_PTO_LATE_LARGEST,
      "an ACK of a packet a probe took acknowledges nothing: the largest acknowledged stays",
      (unsigned long long)(conn->pktns.rtb.largest_acked_tx_pkt_num - pn0), QGO_PTO_LATE_LARGEST);
  ngtcp2_conn_del(conn);
}

/* ---- 0033: a client's transport errors as quic-go closes on them -------------------------- */

/* A packet of the server's carrying |payload| as it is — bytes the frame encoder would not write —
 * at |level| (2 Handshake, 3 1-RTT), read by the client at |ts|. The crypto of this harness is the
 * identity with a tag of zeros and no header protection, so the packet is laid out by hand. */
static int server_sends_raw_ex(ngtcp2_conn *conn, int level, uint8_t first,
                               const uint8_t *payload, size_t len, const uint8_t *tail,
                               ngtcp2_tstamp ts);

static int server_sends_raw(ngtcp2_conn *conn, int level, const uint8_t *payload, size_t len,
                            ngtcp2_tstamp ts)
{
  return server_sends_raw_ex(conn, level, 0x43, payload, len, NULL, ts);
}

/* The same with the first byte of a 1-RTT packet |first| as it is (the header protection mask is
 * zeros) and, when |tail| is not NULL, its 16 bytes in place of the tag. */
static int server_sends_raw_ex(ngtcp2_conn *conn, int level, uint8_t first,
                               const uint8_t *payload, size_t len, const uint8_t *tail,
                               ngtcp2_tstamp ts)
{
  static uint8_t buf[2048];
  static int64_t hs_pn = 100;
  ngtcp2_pkt_info pi = { 0 };
  size_t n = 0;
  int64_t pn;

  if (level == 3) {
    pn = ++server_last_pn;
    buf[n++] = first; /* 0x43: short header, fixed bit, a 4-byte packet number */
    memcpy(buf + n, conn->oscid.data, conn->oscid.datalen);
    n += conn->oscid.datalen;
  } else {
    size_t rest = 4 + len + NGTCP2_FAKE_AEAD_OVERHEAD;

    pn = ++hs_pn;
    /* long header, fixed bit, Initial (level 1) or Handshake, a 4-byte packet number */
    buf[n++] = level == 1 ? 0xc3 : 0xe3;
    ngtcp2_put_uint32be(buf + n, NGTCP2_PROTO_VER_V1);
    n += 4;
    buf[n++] = (uint8_t)conn->oscid.datalen;
    memcpy(buf + n, conn->oscid.data, conn->oscid.datalen);
    n += conn->oscid.datalen;
    buf[n++] = (uint8_t)conn->dcid.current.cid.datalen;
    memcpy(buf + n, conn->dcid.current.cid.data, conn->dcid.current.cid.datalen);
    n += conn->dcid.current.cid.datalen;
    if (level == 1) {
      buf[n++] = 0; /* no token */
    }
    buf[n++] = (uint8_t)(0x40 | (rest >> 8));
    buf[n++] = (uint8_t)rest;
  }
  ngtcp2_put_uint32be(buf + n, (uint32_t)pn);
  n += 4;
  if (len) {
    memcpy(buf + n, payload, len);
  }
  n += len;
  if (tail) {
    memcpy(buf + n, tail, NGTCP2_FAKE_AEAD_OVERHEAD);
  } else {
    memset(buf + n, 0, NGTCP2_FAKE_AEAD_OVERHEAD);
  }
  n += NGTCP2_FAKE_AEAD_OVERHEAD;
  return ngtcp2_conn_read_pkt(conn, &test_path.path, &pi, buf, n, ts);
}

/* Whether the close |conn| would send is |code|, |frame_type| and |reason|; NULL for none. */
static int close_is(ngtcp2_conn *conn, int rv, uint64_t code, uint64_t frame_type,
                    const char *reason, char *got, size_t cap)
{
  ngtcp2_ccerr ccerr;

  if (!ngtcp2_conn_get_qgo_ccerr(conn, &ccerr)) {
    snprintf(got, cap, "no close (%d)", rv);
    return reason == NULL && rv == 0;
  }
  snprintf(got, cap, "0x%llx, frame type 0x%llx, \"%.*s\" (%d)", (unsigned long long)ccerr.error_code,
           (unsigned long long)ccerr.frame_type, (int)ccerr.reasonlen, ccerr.reason, rv);
  return reason != NULL && rv < 0 && ccerr.error_code == code &&
         ccerr.frame_type == frame_type && ccerr.reasonlen == strlen(reason) &&
         memcmp(ccerr.reason, reason, ccerr.reasonlen) == 0;
}

static void test_close_frames(void)
{
  size_t i, bad = 0;
  char got[640], what[160];

  printf("\n0033: a client's transport errors as quic-go closes on them\n");

  /* The frame parser: every payload quic-go's own parser was run over (tools/qgovec). */
  for (i = 0; i < sizeof(qgo_frame_close) / sizeof(qgo_frame_close[0]); ++i) {
    ngtcp2_conn *conn = client_established();
    int rv;

    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    /* Datagrams on, as hysteria's client always has them (src/quic/params.c). */
    conn->local.transport_params.max_datagram_frame_size = 65536;
    rv = server_sends_raw(conn, qgo_frame_close[i].level,
                          (const uint8_t *)qgo_frame_close[i].payload, qgo_frame_close[i].len,
                          1000 * NGTCP2_MILLISECONDS);
    if (!close_is(conn, rv, qgo_frame_close[i].code, qgo_frame_close[i].frame_type,
                  qgo_frame_close[i].reason, got, sizeof(got))) {
      printf("        %s: %s; quic-go 0x%llx, frame type 0x%llx, %s%s%s\n", qgo_frame_close[i].name,
             got, (unsigned long long)qgo_frame_close[i].code,
             (unsigned long long)qgo_frame_close[i].frame_type,
             qgo_frame_close[i].reason ? "\"" : "",
             qgo_frame_close[i].reason ? qgo_frame_close[i].reason : "no close",
             qgo_frame_close[i].reason ? "\"" : "");
      ++bad;
    }
    ngtcp2_conn_del(conn);
  }
  snprintf(what, sizeof(what), "%zu payloads: refused where quic-go's frame parser refuses, in its words",
           sizeof(qgo_frame_close) / sizeof(qgo_frame_close[0]));
  ok(bad == 0, what);

  /* The transport parameters: quic-go's Unmarshal run over each (tools/qgovec). */
  bad = 0;
  for (i = 0; i < sizeof(qgo_tp_close) / sizeof(qgo_tp_close[0]); ++i) {
    char msg[256], full[320];
    int rv = ngtcp2_qgo_transport_params_check((const uint8_t *)qgo_tp_close[i].tp,
                                               qgo_tp_close[i].len, msg, sizeof(msg));

    snprintf(full, sizeof(full), "TRANSPORT_PARAMETER_ERROR (local): %s", msg);
    if (qgo_tp_close[i].reason ? (rv == 0 || strcmp(full, qgo_tp_close[i].reason) != 0) : rv != 0) {
      printf("        %s: %s; quic-go %s\n", qgo_tp_close[i].name, rv ? full : "taken",
             qgo_tp_close[i].reason ? qgo_tp_close[i].reason : "taken");
      ++bad;
    }
  }
  snprintf(what, sizeof(what), "%zu sets of transport parameters: taken or refused as Unmarshal does",
           sizeof(qgo_tp_close) / sizeof(qgo_tp_close[0]));
  ok(bad == 0, what);
}

/* A STREAM frame of the server's on |sid|: |len| bytes at |offset|, FIN when |fin|. */
static int server_stream(ngtcp2_conn *conn, int64_t sid, uint64_t offset, size_t len, int fin,
                         ngtcp2_tstamp ts)
{
  ngtcp2_frame fr;
  ngtcp2_vec data = { null_data, len };

  fr.stream = (ngtcp2_stream){
    .type = NGTCP2_FRAME_STREAM,
    .flags = fin ? NGTCP2_STREAM_FIN_BIT : 0,
    .fin = (uint8_t)fin,
    .stream_id = sid,
    .offset = offset,
    .datacnt = len ? 1 : 0,
  };
  fr.stream.data = &data;
  return server_sends(conn, &fr, 1, ts);
}

static int server_reset(ngtcp2_conn *conn, int64_t sid, uint64_t final_size, ngtcp2_tstamp ts)
{
  ngtcp2_frame fr;

  fr.reset_stream = (ngtcp2_reset_stream){
    .type = NGTCP2_FRAME_RESET_STREAM,
    .stream_id = sid,
    .final_size = final_size,
  };
  return server_sends(conn, &fr, 1, ts);
}

/* NEW_CONNECTION_ID, as tools/qgovec makes it: ID cid_of(|cid|), a token of |token| and zeros. */
static int server_ncid(ngtcp2_conn *conn, uint64_t seq, uint8_t cid, uint8_t token,
                       ngtcp2_tstamp ts)
{
  ngtcp2_frame fr;

  memset(&fr, 0, sizeof(fr));
  fr.new_connection_id.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = seq;
  fr.new_connection_id.cid = cid_of(cid);
  fr.new_connection_id.token.data[0] = token;
  return server_sends(conn, &fr, 1, ts);
}

/* What test/ngpatch sends under each name of qgo_root_close. */
static int root_scenario(ngtcp2_conn *conn, const char *name)
{
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  int rv;

#define IS(S) (strcmp(name, (S)) == 0)
#define ALL(A, B) ((rv = (A)) != 0 ? rv : (B))
  if (IS("STREAM past the stream window")) {
    return server_stream(conn, 1, 6291456, 1, 0, ts);
  }
  if (IS("FIN at 10, then FIN at 20")) {
    return ALL(server_stream(conn, 1, 0, 10, 1, ts), server_stream(conn, 1, 10, 10, 1, ts));
  }
  if (IS("FIN at 10, then data to 16")) {
    return ALL(server_stream(conn, 1, 0, 10, 1, ts), server_stream(conn, 1, 15, 1, 0, ts));
  }
  if (IS("data to 100, then FIN at 50")) {
    return ALL(server_stream(conn, 1, 0, 100, 0, ts), server_stream(conn, 1, 0, 50, 1, ts));
  }
  if (IS("RESET_STREAM past the stream window")) {
    return server_reset(conn, 1, 7000000, ts);
  }
  if (IS("three RESET_STREAMs past the connection window")) {
    return ALL(ALL(server_reset(conn, 1, 6291456, ts), server_reset(conn, 5, 6291456, ts)),
               server_reset(conn, 9, 6291456, ts));
  }
  if (IS("STREAM on the server's bidirectional stream 17, four allowed")) {
    return server_stream(conn, 17, 0, 1, 0, ts);
  }
  if (IS("STREAM on the server's unidirectional stream 3, none allowed")) {
    return server_stream(conn, 3, 0, 1, 0, ts);
  }
  if (IS("MAX_STREAM_DATA on our bidirectional stream 4, not opened")) {
    ngtcp2_frame fr;

    fr.max_stream_data = (ngtcp2_max_stream_data){
      .type = NGTCP2_FRAME_MAX_STREAM_DATA,
      .stream_id = 4,
      .max_stream_data = 1000,
    };
    return server_sends(conn, &fr, 1, ts);
  }
  if (IS("NEW_CONNECTION_ID while zero-length IDs are in use")) {
    conn->dcid.current.cid.datalen = 0;
    return server_ncid(conn, 1, 1, 1, ts);
  }
  if (IS("NEW_CONNECTION_ID 1 twice, another ID")) {
    return ALL(server_ncid(conn, 1, 1, 1, ts), server_ncid(conn, 1, 9, 1, ts));
  }
  if (IS("NEW_CONNECTION_ID 1 twice, another token")) {
    return ALL(server_ncid(conn, 1, 1, 1, ts), server_ncid(conn, 1, 1, 9, ts));
  }
  if (IS("NEW_CONNECTION_ID 1 to 4") || IS("NEW_CONNECTION_ID 1 to 3")) {
    uint64_t seq, last = IS("NEW_CONNECTION_ID 1 to 4") ? 4 : 3;

    for (seq = 1; seq <= last; ++seq) {
      if ((rv = server_ncid(conn, seq, (uint8_t)seq, (uint8_t)seq, ts)) != 0) {
        return rv;
      }
    }
    return 0;
  }
  if (IS("NEW_CONNECTION_ID 0 again, another ID")) {
    return server_ncid(conn, 0, 9, 9, ts);
  }
  if (IS("1-RTT CRYPTO past 16384")) {
    static const uint8_t p[] = { 0x06, 0x7f, 0xfc, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    return server_sends_raw(conn, 3, p, sizeof(p), ts);
  }
  if (IS("empty 1-RTT CRYPTO at 20000")) {
    static const uint8_t p[] = { 0x06, 0x80, 0x00, 0x4e, 0x20, 0x00 };
    return server_sends_raw(conn, 3, p, sizeof(p), ts);
  }
  if (IS("Handshake CRYPTO after the level changed")) {
    static const uint8_t a[] = { 0x06, 0x00, 0x05, 1, 2, 3, 4, 5 };
    static const uint8_t b[] = { 0x06, 0x05, 0x05, 1, 2, 3, 4, 5 };
    return ALL(server_sends_raw(conn, 2, a, sizeof(a), ts), server_sends_raw(conn, 2, b, sizeof(b), ts));
  }
  if (IS("Handshake CRYPTO left over when the level changed")) {
    static const uint8_t a[] = { 0x06, 0x0a, 0x05, 1, 2, 3, 4, 5 };
    static const uint8_t b[] = { 0x06, 0x00, 0x05, 1, 2, 3, 4, 5 };
    return ALL(server_sends_raw(conn, 2, a, sizeof(a), ts), server_sends_raw(conn, 2, b, sizeof(b), ts));
  }
#undef ALL
#undef IS
  printf("        no scenario for \"%s\"\n", name);
  return -9999;
}

static void test_close_root(void)
{
  size_t i, bad = 0;
  char got[640], what[160];

  for (i = 0; i < sizeof(qgo_root_close) / sizeof(qgo_root_close[0]); ++i) {
    ngtcp2_conn *conn = client_established();
    int rv;

    if (strncmp(qgo_root_close[i].name, "Handshake CRYPTO", 16) == 0) {
      /* Still in its handshake, its 1-RTT read key in: the moment quic-go finishes the Handshake
       * CRYPTO stream, and CRYPTO frames still go the full way to TLS. */
      conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
      conn->flags &= ~(uint32_t)(NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                                 NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED);
    } else {
      conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
    }
    rv = root_scenario(conn, qgo_root_close[i].name);
    if (!close_is(conn, rv, qgo_root_close[i].code, 0, qgo_root_close[i].reason, got,
                  sizeof(got))) {
      printf("        %s: %s; quic-go 0x%llx, %s%s%s\n", qgo_root_close[i].name, got,
             (unsigned long long)qgo_root_close[i].code, qgo_root_close[i].reason ? "\"" : "",
             qgo_root_close[i].reason ? qgo_root_close[i].reason : "no close",
             qgo_root_close[i].reason ? "\"" : "");
      ++bad;
    }
    ngtcp2_conn_del(conn);
  }
  snprintf(what, sizeof(what),
           "%zu cases of streams, windows, Connection IDs and CRYPTO: closed as quic-go's own "
           "code closes",
           sizeof(qgo_root_close) / sizeof(qgo_root_close[0]));
  ok(bad == 0, what);
}

/* The checks quic-go makes in its connection and handshake code, which tools/qgovec cannot run
 * (the root package needs what the build container does not hold): their words are held to
 * vendor/quic-go by `make check-qgo-reasons`, and here to what the patched ngtcp2 says. */
static void test_close_conn(void)
{
  size_t bad = 0;
  char got[640], want[256];
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  ngtcp2_conn *conn;
  ngtcp2_frame fr;
  int rv;

#define EXPECT(RV, CODE, REASON)                                                                 \
  do {                                                                                           \
    if (!close_is(conn, (RV), (CODE), 0, (REASON), got, sizeof(got))) {                          \
      printf("        line %d: %s; quic-go 0x%llx, \"%s\"\n", __LINE__, got,                      \
             (unsigned long long)(CODE), (REASON));                                              \
      ++bad;                                                                                     \
    }                                                                                            \
    ngtcp2_conn_del(conn);                                                                       \
  } while (0)
#define ESTABLISHED()                                                                            \
  do {                                                                                           \
    conn = client_established();                                                                 \
    conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;                                         \
  } while (0)

  /* An ACK for a packet never sent (sent_packet_handler.go:406-412). */
  ESTABLISHED();
  EXPECT(server_acks(conn, 0, 1000, 0, ts), 0xa, "received ACK for an unsent packet");

  /* An ACK covering a number the client skipped (:575-585). */
  ESTABLISHED();
  {
    int64_t sid, pn;
    ngtcp2_tstamp t = ts;

    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    conn->pktns.tx.skip_pkt.next_pkt_num = conn->pktns.tx.last_pkt_num + 1;
    pn = client_sends(conn, sid, 100, &t);
    snprintf(want, sizeof(want), "received an ACK for skipped packet number: %lld (1-RTT)",
             (long long)(pn - 1));
    rv = server_acks(conn, pn - 1, pn, 0, t);
  }
  EXPECT(rv, 0xa, want);

  /* RETIRE_CONNECTION_ID past what was issued, and of the ID the packet was sent to
   * (conn_id_generator.go:99-117). */
  ESTABLISHED();
  fr.retire_connection_id = (ngtcp2_retire_connection_id){
    .type = NGTCP2_FRAME_RETIRE_CONNECTION_ID,
    .seq = 100,
  };
  snprintf(want, sizeof(want), "retired connection ID 100 (highest issued: %llu)",
           (unsigned long long)conn->scid.last_seq);
  EXPECT(server_sends(conn, &fr, 1, ts), 0xa, want);

  ESTABLISHED();
  fr.retire_connection_id.seq = 0;
  EXPECT(server_sends(conn, &fr, 1, ts), 0xa,
         "retired connection ID 0 (cc010203), which was used as the Destination Connection ID "
         "on this packet");

  /* PATH_RESPONSE with the path manager off (connection.go:2101-2111). */
  ESTABLISHED();
  memset(&fr, 0, sizeof(fr));
  fr.path_response.type = NGTCP2_FRAME_PATH_RESPONSE;
  EXPECT(server_sends(conn, &fr, 1, ts), 0xa, "unexpected PATH_RESPONSE frame");

  /* Reserved bits, and an empty packet (packet_unpacker.go:113-123, connection.go:1442-1446). */
  ESTABLISHED();
  {
    static const uint8_t ping[] = { 0x01 };
    EXPECT(server_sends_raw_ex(conn, 3, 0x5b, ping, sizeof(ping), NULL, ts), 0xa,
           "invalid reserved bits");
  }
  ESTABLISHED();
  EXPECT(server_sends_raw(conn, 3, NULL, 0, ts), 0xa, "empty packet");

  /* The same packet ending in the active ID's stateless reset token is a stateless reset, which
   * quic-go answers with a close of its own (connection.go:1220-1233, :2879-2892). */
  ESTABLISHED();
  {
    static const uint8_t ping[] = { 0x01 };
    uint8_t token[NGTCP2_STATELESS_RESET_TOKENLEN];

    memset(token, 0x55, sizeof(token));
    memcpy(conn->dcid.current.token.data, token, sizeof(token));
    conn->dcid.current.flags |= NGTCP2_DCID_FLAG_TOKEN_PRESENT;
    rv = server_sends_raw_ex(conn, 3, 0x5b, ping, sizeof(ping), token, ts);
  }
  EXPECT(rv, 0x1, "connection BUG: unspecified error type (msg: received a stateless reset)");

  /* An error in an Initial packet closes the connection, as in any other (connection.go:
   * 1763-1766); upstream dropped the packet. On a client still in its handshake. */
  ESTABLISHED();
  conn->state = NGTCP2_CS_CLIENT_WAIT_HANDSHAKE;
  conn->flags &= ~(uint32_t)(NGTCP2_CONN_FLAG_TLS_HANDSHAKE_COMPLETED |
                             NGTCP2_CONN_FLAG_HANDSHAKE_CONFIRMED |
                             NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED);
  {
    static const uint8_t unknown[] = { 0x01, 0x1f, 0x00, 0x00 };
    rv = server_sends_raw_ex(conn, 1, 0, unknown, sizeof(unknown), NULL, ts);
    if (!close_is(conn, rv, 0x7, 0x1f, "unknown frame type", got, sizeof(got))) {
      printf("        an unknown frame in an Initial packet: %s; quic-go 0x7, frame type 0x1f, "
             "\"unknown frame type\"\n", got);
      ++bad;
    }
    ngtcp2_conn_del(conn);
  }

  /* checkTransportParameters (connection.go:2422-2450), on a client that has not had any. */
  {
    ngtcp2_transport_params params;

    conn = client_new(0, NULL);
    ngtcp2_transport_params_default(&params);
    params.initial_scid = cid_of(1);
    params.initial_scid_present = 1;
    params.original_dcid = conn->rcid;
    params.original_dcid_present = 1;
    EXPECT(ngtcp2_conn_set_remote_transport_params(conn, &params), 0x8,
           "expected initial_source_connection_id to equal c000000000000000, is "
           "c000000000000001");

    conn = client_new(0, NULL);
    params.initial_scid = conn->dcid.current.cid;
    params.original_dcid = cid_of(2);
    EXPECT(ngtcp2_conn_set_remote_transport_params(conn, &params), 0x8,
           "expected original_destination_connection_id to equal c000000000000000, is "
           "c000000000000002");

    conn = client_new(0, NULL);
    params.original_dcid = conn->rcid;
    params.retry_scid = cid_of(3);
    params.retry_scid_present = 1;
    EXPECT(ngtcp2_conn_set_remote_transport_params(conn, &params), 0x8,
           "received retry_source_connection_id, although no Retry was performed");
  }

  /* The whole way in: quic-go's parse first, then ngtcp2's decode without what quic-go does not
   * read. */
  {
    static const uint8_t dup[] = { 0x00, 0x08, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0x08, 0xc0, 0, 0,
                                   0, 0, 0, 0, 0, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02 };
    static const uint8_t vi[] = { 0x00, 0x08, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x0f, 0x08, 0xc0, 0, 0,
                                  0, 0, 0, 0, 0, 0x11, 0x03, 0x01, 0x02, 0x03 };

    conn = client_new(0, NULL);
    EXPECT(ngtcp2_conn_decode_and_set_remote_transport_params(conn, dup, sizeof(dup)), 0x1,
           "TRANSPORT_PARAMETER_ERROR (local): received duplicate transport parameter 0x4");

    conn = client_new(0, NULL);
    rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, vi, sizeof(vi));
    if (rv != 0) {
      printf("        version_information quic-go does not read was refused: %d\n", rv);
      ++bad;
    }
    ngtcp2_conn_del(conn);
  }
#undef ESTABLISHED
#undef EXPECT

  ok(bad == 0, "the checks of quic-go's connection code: refused as it refuses, in its words");
}


/* ---- 0033, Q10: the last three differences on the transport ------------------------------ */

/* RETIRE_CONNECTION_ID frames for |seq| waiting in the 1-RTT queue. */
static size_t retires_queued(const ngtcp2_conn *conn, uint64_t seq)
{
  const ngtcp2_frame_chain *frc;
  size_t n = 0;

  for (frc = conn->pktns.tx.frq; frc; frc = frc->next) {
    if (frc->fr.hd.type == NGTCP2_FRAME_RETIRE_CONNECTION_ID && frc->fr.retire_connection_id.seq == seq) {
      ++n;
    }
  }
  return n;
}

static ngtcp2_frame ncid(uint64_t seq, uint64_t retire_prior_to)
{
  ngtcp2_frame fr;

  memset(&fr, 0, sizeof(fr));
  fr.new_connection_id.type = NGTCP2_FRAME_NEW_CONNECTION_ID;
  fr.new_connection_id.seq = seq;
  fr.new_connection_id.retire_prior_to = retire_prior_to;
  fr.new_connection_id.cid = cid_of((uint8_t)seq);
  memset(fr.new_connection_id.token.data, (int)seq, sizeof(fr.new_connection_id.token.data));
  return fr;
}

static void test_q10(void)
{
  ngtcp2_tstamp ts = 1000 * NGTCP2_MILLISECONDS;
  char got[640];
  ngtcp2_conn *conn;
  ngtcp2_frame fr[40];
  size_t i;
  int rv;

  printf("\n0033, Q10: the last three differences from quic-go on the transport\n");

  /* A NEW_CONNECTION_ID below Retire Prior To is answered with a RETIRE_CONNECTION_ID each time it
   * arrives, as connIDManager.add queues one each time (vendor/quic-go/conn_id_manager.go:86-93). */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  fr[0] = ncid(5, 3);
  rv = server_sends(conn, fr, 1, ts);
  fr[0] = ncid(1, 0);
  fr[1] = ncid(1, 0);
  rv = rv != 0 ? rv : server_sends(conn, fr, 2, ts);
  fr[0] = ncid(1, 0);
  rv = rv != 0 ? rv : server_sends(conn, fr, 1, ts);
  ok(rv == 0 && retires_queued(conn, 1) == 3,
     "a NEW_CONNECTION_ID already retired, three times: three RETIRE_CONNECTION_ID, as quic-go queues");
  ngtcp2_conn_del(conn);

  /* maxControlFrames: 16384 queued is allowed, one more closes with INTERNAL_ERROR, no frame type
   * and no reason (vendor/quic-go/framer.go:18, :119-122; connection.go:616-619). Queued the way a
   * node can queue them: reordered NEW_CONNECTION_ID frames, forty to a packet. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  fr[0] = ncid(5, 3);
  rv = server_sends(conn, fr, 1, ts);
  {
    size_t queued = 0;
    const ngtcp2_frame_chain *frc;

    for (i = 0; i < 40; ++i) {
      fr[i] = ncid(1, 0);
    }
    /* Everything already queued counts, whatever it is: up to exactly 16384. */
    for (frc = conn->pktns.tx.frq; frc; frc = frc->next) {
      ++queued;
    }
    while (rv == 0 && queued < 16384) {
      size_t k = 16384 - queued < 40 ? 16384 - queued : 40;
      rv = server_sends(conn, fr, k, ts);
      queued += k;
    }
    rv = rv != 0 ? rv : ngtcp2_conn_qgo_check_control_frames(conn);
    ok(rv == 0, "16384 control frames queued: the connection goes on");
    rv = server_sends(conn, fr, 1, ts);
    rv = rv != 0 ? rv : ngtcp2_conn_qgo_check_control_frames(conn);
    ok(close_is(conn, rv, 0x1, 0, "", got, sizeof(got)),
       "16385: closed with INTERNAL_ERROR, no frame type, no reason, as quic-go's run loop closes");
    if (!close_is(conn, rv, 0x1, 0, "", got, sizeof(got))) {
      printf("        %s\n", got);
    }
  }
  ngtcp2_conn_del(conn);

  /* An ACK frame read for all its ranges, as parseAckFrame reads them
   * (vendor/quic-go/internal/wire/ack_frame.go:66-90): seventy ranges past the first, each one
   * packet, and every one of the seventy-one packets leaves flight. Upstream read 63 and skipped
   * the rest, so the last seven stayed in flight. */
  conn = client_established();
  conn->flags |= NGTCP2_CONN_FLAG_HANDSHAKE_COMPLETED;
  {
    static int64_t pns[160];
    static ngtcp2_ack_range ranges[80];
    ngtcp2_frame ack;
    int64_t sid;
    ngtcp2_tstamp t = ts;
    size_t sent = 0, acked = 0, k;
    ngtcp2_strm *strm;

    ngtcp2_conn_open_bidi_stream(conn, &sid, NULL);
    while (sent < 145) {
      int64_t pn = client_sends(conn, sid, 20, &t);
      if (pn < 0) {
        break;
      }
      pns[sent++] = pn;
    }
    /* A hundred and forty-five packets are past quic-go's first key update, at a hundred
     * (FirstKeyUpdateInterval, patches/ngtcp2/0026), and an ACK reaching the new keys from a peer
     * that never followed closes the connection. The server follows: a PING in the new key phase. */
    {
      static const uint8_t ping[] = { 0x01 };
      rv = server_sends_raw_ex(conn, 3, 0x43 | NGTCP2_SHORT_KEY_PHASE_BIT, ping, sizeof(ping), NULL,
                               t);
    }
    /* The newest packet, then every second one below it: 71 packets, 70 ranges. */
    memset(&ack, 0, sizeof(ack));
    ack.ack.type = NGTCP2_FRAME_ACK;
    ack.ack.largest_ack = pns[sent - 1];
    ack.ack.first_ack_range = 0;
    ack.ack.ranges = ranges;
    for (i = 0; i < 70 && 2 * (i + 1) < sent; ++i) {
      int64_t prev = pns[sent - 1 - 2 * i], cur = pns[sent - 1 - 2 * (i + 1)];
      ranges[i].gap = (uint64_t)(prev - cur - 2);
      ranges[i].len = 0;
    }
    ack.ack.rangecnt = i;
    server_pkt_flags = NGTCP2_PKT_FLAG_KEY_PHASE;
    rv = server_sends(conn, &ack, 1, t);
    server_pkt_flags = 0;
    /* Acknowledged is what the stream records as acknowledged: packet k carried the twenty bytes at
     * 20k. The gaps are declared lost and leave the history too, so counting what left it would
     * not tell the two apart. */
    strm = ngtcp2_conn_find_stream(conn, sid);
    for (k = 0; strm != NULL && strm->tx.acked_offset != NULL && k < sent; ++k) {
      acked += ngtcp2_gaptr_is_pushed(strm->tx.acked_offset, 20 * k, 20) != 0;
    }
    ok(sent == 145 && ack.ack.rangecnt == 70 && rv == 0 && acked == 71,
       "an ACK of 70 ranges past the first: all 71 packets acknowledged, as quic-go reads them");
    if (!(sent == 145 && ack.ack.rangecnt == 70 && rv == 0 && acked == 71)) {
      (void)close_is(conn, rv, 0, 0, NULL, got, sizeof(got));
      printf("        sent %zu, ranges %zu, rv %d, acknowledged %zu: %s\n", sent, ack.ack.rangecnt,
             rv, acked, got);
    }
  }
  ngtcp2_conn_del(conn);
}

int main(void)
{
  test_long_header();
  test_pkt_numlen();
  test_first_initial();
  test_dcid();
  test_flow();
  test_retransmit_order();
  test_loss_threshold();
  test_rtt();
  test_retry();
  test_skip();
  test_payload();
  test_datagram_room();
  test_rtxq();
  test_rtx_room();
  test_streams_blocked();
  test_key_update();
  test_close_mid_handshake(0);
  test_close_mid_handshake(1);
  test_confirm_on_ack();
  test_ack_ranges();
  test_ecn();
  test_history();
  test_probe();
  test_close_frames();
  test_close_root();
  test_close_conn();
  test_q10();

  printf("\n%s\n", failures == 0 ? "all good" : "FAILURES");
  return failures == 0 ? 0 : 1;
}
