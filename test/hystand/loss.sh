#!/bin/sh
# The same transfer through the same impaired path, once with this client and once with the
# reference — which is the only way to see what the congestion controller costs.
#
# WHY THIS EXISTS. Both clients run BBR, and they are not the same BBR: hysteria hands quic-go its
# own Chromium-derived sender (vendor/hysteria/core/internal/congestion/bbr, reached through
# UseConfigured when no bandwidth is stated, client/client.go:153-166), while this client runs ngtcp2's,
# which is the later draft. On a clean path the difference is invisible — test/hystand measures 700+
# Mbit/s for both because nothing is lost and nothing is queued. It shows up where a controller
# earns its keep: loss and delay. This puts a number on it before anybody decides whether porting
# 2600 lines of Go is worth it. (It was: the port is patches/ngtcp2/0009, and tools/vendorcap/bbrcmp
# shows it computing what the reference computes, round for round. This stand is now a regression
# check rather than a question.)
#
# The path is impaired by a relay of our own between the client and the node (test/hystand/impair):
# both clients meet the same delay and the same loss, drawn from the same seed, and neither sees
# anything about the other. netem would have done it too, and the build image has no tc — asking for
# NET_ADMIN to get one would make this stand need a privilege nothing else here needs.
#
# ⚠️ BOTH CLIENTS ARE DRIVEN THROUGH ONE SHAPE: a local TCP port that forwards to the echo target.
# This client has that natively (transparent mode with -t); the reference has `tcpForwarding`
# (vendor/hysteria/app/cmd/client.go:892-894, :1048). Driving one through SOCKS5 and the other
# through a forwarder would have measured the proxy layers as well as the transport.
#
# ⚠️ LOSS IS RANDOM, SO ONE RUN MEANS LITTLE. Three transfers per client per setting, alternating
# settings but not clients: a client is started once per setting and torn down, because a fresh
# connection is what the loss is being measured against.
#
# ⚠️⚠️ AND THE STAND ITSELF WAS THE FIRST THING IT MEASURED WRONG. Until 19 September the delay was
# a time.AfterFunc per packet: a timer and a goroutine each, fired in whatever order the runtime
# chose. That is not a delay line, it is a reordering box — and a QUIC sender answers reordering
# with loss detection, which the two clients do not do identically. Every number this stand printed
# before that fix was measured through a path that impaired the two clients DIFFERENTLY.
#
# What it had been saying: at 1 % loss this client did 115 · 158 · 182 Mbit/s against the
# reference's 108 · 101 · 90, and the conclusion drawn from it — written into two documents — was
# that porting the reference's congestion control buys likeness and costs speed.
#
# What an ordered path says, three runs of three transfers each:
#
#   1 % loss      ours 245 · 343 · 335 | 253 · 379 · 410 | 244 · 346 · 319
#                 ref  281 · 347 · 393 | 241 · 311 · 383 | 274 · 369 · 381
#   clean         ours 319 · 514 · 509      ref 328 · 422 · 445
#
# Both are two to four times faster than the old stand reported, and they overlap: on this path,
# after the port, there is no speed difference to speak of — the earlier one was the reordering,
# and it happened to fall in this client's favour.
#
# AND THE SHAPE, WHICH IS THE OTHER HALF OF THE QUESTION. A throughput number says who finished
# first; it says nothing about what the path saw, and what a path sees of a QUIC sender without
# decrypting anything is WHEN its datagrams arrive. The relay reports that too (-shape): the gaps
# between datagrams from the client, as a histogram, and the runs that arrived together.
#
# Measured 19 September on an ORDERED path, clean, 25 ms each way, three transfers of 16 MB up and
# back (the numbers before the fix are kept above, as what a reordering path made of the same two
# clients):
#
#                 datagrams   bytes     gaps p50 / p90 / p99      back-to-back (<50us)
#   ours             38 208   51.6 MB   2us / 127us / 427us       84 %
#   reference        45 995   55.2 MB   1us /  18us / 898us       94 %
#
# (One run each, and the density figure moves two or three points between runs — 81 to 84 here, 92 to
# 94 for the reference. Read the CHANGES below rather than the absolute number, and read them against
# a baseline taken the same afternoon.)
#
# The reference packs tighter — nine in ten of its datagrams arrive in the same batch as the one
# before, against eight in ten here — and three things were tried against that, which is why the
# number below is worth trusting:
#
#   the pacer          the reference's bucket, asked per packet the way its send loop asks it
#                      (patch 0009 exports it, src/quic/conn.c consults it): 80 % -> 80 %
#   the batch          LC_GSO_BATCH 8 -> 14, which is what the reference's 20 KB GSO buffer holds
#                      at 1441 bytes: 80 % -> 81 %, and the commonest run became exactly 14
#   a larger window    the same measurement at 50 ms one way instead of 25: 78 %
#
# So it is not the controller, not the pacer and not the batch size. What is left is how much this
# client has ready when it writes: one loop reads from the LAN, feeds the queue and writes, where the
# reference has a goroutine for each — its syscalls follow one another, ours are separated by the
# work between them.
#
# AND THE FOURTH THING TRIED IS THE ONE THAT WORKED, later the same day. That sentence had been
# reasoning until the write loop was made to count why it stopped (src/quic/conn.h, tx_stop_dry —
# this stand prints the line below): on THIS path seven passes in ten ended with nothing left to
# write. Not starved for want of a bigger batch — starved for want of a feed, because the uplink
# read happened once per event while the reference's io.Copy reads, writes and reads again. Rounding
# that read (HY_READ_ROUNDS in cmd/lc-tunnel/main.c, since replaced by the reader thread of
# src/net/reader.c, which reads as much as there is room for) moved the same measurement:
#
#   the feed           read up to four bufferfuls per event instead of one, each handed to the
#                      stream before the next is taken: 81 % -> 86, 86, 85 % over three runs
#                      against the reference's 93, 93, 91 — so five or six points behind where it
#                      had been eleven. The commonest runs became ~900 batches of fourteen, with
#                      runs of twenty-four appearing for the first time.
#   twice that         eight instead of four: 85 %, p90 gap 168us against 144 — bigger bursts,
#                      longer pauses. Measured and rejected; do not try it again.
#
# ⚠️ AND THE FIFTH THING TRIED IS THE ONE THAT MOVED tx_stop_dry, 2026-09-20. Everything above is about
# how much the READER stages, and none of it moved that counter. The hand-off did: the staged
# bytes reached the stream once per turn of the event loop, so ngtcp2 ran out, the write loop went
# back to poll, and the next feed waited for whatever woke it. The reference never waits — its
# writer is a goroutine parked inside Stream.Write, and the packer releases it the instant it takes
# the last frame (send_stream.go:307-322, 492). So the write loop now ASKS: see lc_qrefill_fn in
# src/quic/conn.h and hy_refill in cmd/lc-tunnel/main.c.
#
#   the hand-off    the write loop asks the tunnel to top the streams up when ngtcp2 has run out,
#                   once between packets: dry passes 5 345 and 3 898 became 1 266 and 2 005, and
#                   datagrams per pass went from 4 to 6-7. Density 87 %, unchanged.
#
#
# ⚠️ AND THE HAND-OFF RULED OUT ONE MORE EXPLANATION ON ITS WAY PAST, which is worth a line because
# it was the obvious one. If our standalone acknowledgements were mostly what the loop emits when it
# has nothing else — the reference being denser because it runs out more often and fills those
# moments — then cutting our dry passes should have cut our small datagrams with them. It did not:
# across the four runs above, dry passes went 5 812 · 5 345 to 1 266 · 2 005, a fall of 71 %, while
# datagrams under 300 bytes went 1 982 · 1 898 to 1 611 · 1 766, a fall of 13 %. The two are not the
# same thing, and the reference's 13.8 % is not explained by our 4.3 %.

# ⚠️⚠️ AND THE DENSITY STILL DID NOT MOVE, which is the fourth time that number has refused to, so
# it is worth saying plainly what has now been ruled out. The reference packs 93 % against our 87,
# and it is NOT the congestion controller (its phases match), NOT the pacer (it is the reference's
# own bucket), NOT the batch size, NOT the feed, NOT the acknowledgement path, NOT the 32 KB seam
# and NOT the hand-off. What this paragraph then said was left — the reference sending more
# datagrams, each smaller — did not survive a one-way measurement: see the section below that begins
# "AND THEN ONE MEASUREMENT OVERTURNED".
#
# MEASURED ON THE ROUTER TOO, which is where the gap against the reference was recorded in the
# first place. Both binaries were run at once on the Xiaomi against the node carrying it, on ports
# 19991 and 19992, with uploads alternated between them so the path could not favour either:
#
#                 dry passes per MB uploaded        yields per interval
#   before        29.2  then  21.2                  854, 491
#   after         10.2  then   6.0                  982, 945
#
# Throughput over those seven alternating 5 MB uploads averaged 1.59 MB/s before and 1.77 after,
# which is +11 % — and is NOT claimed: the path itself moved by a factor of two during the run
# (2.59 MB/s on one round, 1.30 on the next, for both binaries alike), and in the slow regime the
# two were identical. What the run establishes is the counter, three times lower per megabyte, and
# that is the thing the change was aimed at.
#
# 🔴 AND THEN ONE MEASUREMENT OVERTURNED THE EXPLANATION THIS FILE HAD SETTLED ON, 2026-09-21.
#
# Every transfer this stand made was symmetric: the loader sends and reads the same bytes back, so
# both directions carry data at once and a client's outgoing datagrams are a MIXTURE of its own
# stream data and its acknowledgements for the return stream. "Small at this MTU" means either a
# bare acknowledgement or a partial data packet, and a symmetric transfer cannot tell them apart.
# So the paragraphs above reasoned from a number that could not be taken apart.
#
# SINK=1 takes it apart. The far end becomes a port that answers one byte per megabyte and nothing
# else (test/hystand/echo), so the return stream is acknowledgements only — and acknowledgements
# do not elicit acknowledgements. What a client then sends is its own data and nothing else:
#
#                  datagrams   mean   under 300 B   gaps p50/p90/p99       back-to-back   runs
#   ours            38 513     1369     0.2 %       1 / 25 / 1183 us          90 %        1 971x14
#   reference       39 239     1380     0.9 %       1 /  3 / 1169 us          97 %        48x2, 22x4
#
# THE REFERENCE'S EXTRA SMALL DATAGRAMS WERE ITS ACKNOWLEDGEMENTS, and so was "more, smaller": with
# nothing to acknowledge, both send the same number of datagrams of the same size. Everything this
# file and src/quic/conn.h said about the reference packing denser BECAUSE it sends more, smaller
# packets was a reading of the mixture.
#
# What survives is the density itself, 97 % against 90, and its shape. Ours arrive in runs of
# exactly fourteen — one GSO batch, LC_GSO_BATCH — with a gap after each; the reference's arrive in
# long runs of no particular length (the longest seen, 48 and 100 in a row), which is several
# batches handed to the kernel with nothing between them. The difference is not WHAT is in the
# packets. It is how many batches leave before the send loop stops.
#
# TRIED AGAINST THAT, ONE WAY, AND RULED OUT — each one measured, not reasoned:
#
#   the reader-first yield     switched off: 87 % and p90 98 us — worse. It stays.
#   our GSO                    switched off (with the yield also off): 71 % against 87 — worse.
#   the pacer's burst          HYBBR_MAX_BURST_PACKETS 10, the delay multiplier 4 and a millisecond
#                              floor are the reference's to the digit
#                              (vendor/hysteria/core/internal/congestion/common/pacer.go:11-12,
#                              params.go:120).
#   another quic-go            vendor/quic-go is at 599b15a1, the revision hysteria's go.mod pins.
#   one clock per pass         quic-go reads `now` once per send cycle and hands the same value to
#                              SendMode, the packer and the pacer
#                              (vendor/quic-go/connection.go:2486-2489,
#                              2618-2638); this loop read the clock per packet. Done its way: 86 %,
#                              p90 102 us, stops on the pace 5 849 against 2 433 — worse, because a
#                              frozen clock stops the bucket refilling inside a pass. Structurally
#                              closer and further from the reference on the wire, which is the thing
#                              that counts, so it was taken back out.
#
# ⚠️ A TRAP THAT COST TWO OF THOSE RUNS: the switches used to try them were environment variables
# read with `getenv(...) == NULL`, and `docker run -e VAR=` sets VAR to the EMPTY STRING rather
# than leaving it unset — so once a switch was wired through, every later run had that feature off
# whether it was asked for or not. The one-clock run and the GSO run above were each measured
# again, or reinterpreted, once that was seen.
#
# 🔴 AND THE CAUSE, MEASURED, 2026-09-21. The runs of exactly fourteen are the time it takes to PACK
# the next batch, and the reference does not pay it because it packs and sends at the same time.
#
# Timed with a clock around the sendmsg of every GSO batch, on the one-way stand: 33 microseconds
# on average over 4 000 batches of fourteen datagrams. The threshold for "back to back" in this
# report is 50. So the sequence here is: send batch N (33 us), THEN encrypt and frame the fourteen
# packets of batch N+1, THEN send it — and the gap between the last datagram of N and the first of
# N+1 is the packing time, which is regularly past 50 us. A run ends at fourteen because that is
# where the syscall is.
#
# The reference's Send does not make a syscall. It puts the batch on a channel of eight and returns
# ("guaranteed to not block", vendor/quic-go/send_queue.go:47-64, sendQueueCapacity = 8 at :35), and
# a goroutine of its own takes batches off it and writes them (Run, :78-108). So while that
# goroutine is inside sendmsg for batch N, the connection's own goroutine is already packing N+1,
# and when the write returns the next batch is waiting. Several batches leave with nothing between
# them — the runs of 48 and 100 above — until the pacer or the queue says stop.
#
# That also says why every change to this loop's timing left the density where it was: each of them
# moved WHEN the loop packs, and none of them could move the fact that packing and sending here are
# one after the other on one thread. The reference's connection algorithm has two parties, and this
# one had one.
#
# ⚠️ THE SECOND PARTY WENT IN THE SAME DAY — src/quic/sendq.{c,h}, the reference's queue of eight with
# a writer thread — AND THE RUNS ARE STILL FOURTEEN. So the paragraphs above name something true that
# is not the cause. Old and new binaries against the reference, three interleaved rounds, one way:
#
#                 back to back (<50 us)       commonest run
#   before        90 %  91 %  86 %            1399x14  1642x14  787x14
#   with queue    90 %  89 %  90 %            446x14   440x14   675x14
#   reference     97 %  96 %  96 %            40x2     42x2     47x2
#
# Clocks inside the client said why: a full batch took 218 us to PACK against 32-36 us to send, and
# at 5 838 of 6 731 commits the queue was empty — the writer waits for the packer, not the other
# way round, so there is no sendmsg to hide behind the packing.
#
# ⚠️ AND THE PACKING WAS NOT THE AEAD, which is what this paragraph said for an hour. It blamed the
# cipher — on this x86 machine both clients put AES-128-GCM first, ours is the router's portable
# code and the reference's is AES-NI assembly — and that was a real difference, so the stand was
# made fair (GENERIC below) to take it out. With ChaCha20 on both sides and the reference on plain
# Go, a batch still took 173-200 us, and clocks on every part of the iteration found where: the
# ngtcp2 write call, crypto included, was 3.7 us a packet, and lc_qtx_run was 10.6 — walking the
# list of blocks still in flight, several hundred of them on this path, from the head, up to four
# times a packet, to find where the unsent bytes begin. A pointer that remembers it
# (src/quic/txbuf.c) took that to 57 ns, the iteration from 15.9 us to 5.7 and the batch from 200 us
# to 54. The runs of fourteen went with it; ours now run 2, 3 and 7 most often, like the reference's.
#
#                 back to back (<50 us), fair stand      p90 gap
#   before        90 %  91 %  89 %                       58  9  74 us
#   after         90 %  92 %  92 %                       37  6   9 us
#   reference     96 %  97 %  96 %                        4  3   3 us
#
# ⛔ AND IT IS NOT THE CONTROLLER'S PHASE, which this paragraph said for half an hour on the strength
# of one run: with HYSTERIA_BBR_DEBUG=1 the reference printed no DRAIN in three 16 MB transfers while
# ours went STARTUP -> DRAIN -> PROBE_BW. Two more runs with the same line printed at every round
# start on BOTH sides — estimate, the round's app-limited flag, rounds without growth, prior
# in-flight, the target window — had both leaving STARTUP, ours after 36 and 25 rounds, the
# reference after 20 and 33. That is run-to-run spread, and so is the one run that started this.
# What separates the two is still open.
#
# WHAT IS KNOWN ABOUT IT, 2026-09-21, from two measurements:
#
#   - Clocks on every stop of our write loop: half of the stops on the pacer (624 of ~1 280) are
#     followed by a full millisecond on the pacer's own timer, with not one datagram read in
#     between. The pacer is the reference's and so is the floor; what is missing is the
#     acknowledgement that would have woken the loop sooner.
#   - The relay now reports what the node sends back as well ("<- node" below the client's shape),
#     and on a one-way transfer that is almost nothing but acknowledgements. Same server, same path:
#
#                   datagrams   mean     gaps <50us    gaps 1-5 ms
#     to ours         4 814     35 B       30 %           882
#     to reference    3 819     49 B       52 %           268
#
#     and our own pauses of 1-5 ms are three times the reference's too (1 204 against 362).
#
# So the ack clock ours runs on has holes the reference's does not, and the holes line up with our
# own pauses one round trip earlier: a pause in sending comes back as a pause in acknowledgements,
# which is waited out on the pacer's timer, which is a pause in sending. What starts the first one
# is the open question; that it feeds itself is what these two numbers say.
#
# ✅ AND WHAT STARTED IT WAS OURS, found the same afternoon by counting inside a COPY of quic-go
# (vendor/ untouched): over the same three transfers the reference's triggerSending found the pacer
# saying no 19 times in 3 162 calls, where 8 655 of our 10 141 write passes ended on it. The pacer is
# the reference's; what differed was how often it was CHARGED. ngtcp2 charges every ack-eliciting
# packet through the port's on_pkt_sent, and the write loop charged it a second time — every data
# packet cost the bucket twice its size, so we kept half the pace our controller set (see the note
# at the end of flush in src/quic/conn.c). Charged once:
#
#                   back to back    p90 gap    ack holes 1-5 ms    Mbit/s one way
#   charged twice   90-93 %         5-74 us    451-1 073           184-270
#   charged once    95 · 94 %       4 us       253 · 291           242-326
#   reference       97 · 96 %       3-4 us     284 · 250           210-257
#
# The clean path of run.sh says the same louder: 32 MB up and back in 0.78 s, 690 Mbit/s, where it
# had read 4-9 s since the day the per-packet ask went in.
#
# WHAT IS LEFT AFTER THAT, and why it is left. Pauses of 1-5 ms and over now match the reference
# (466 · 67 against 470 · 74); the rest is SHORT pauses, 50 us to 1 ms: 1 459 against 718. Clocks on
# the writer put 1 182 of them between two batches of one pass — the batch packs in 54 us, sends in
# 25, the writer idles ~30 us and then takes 36 us on average to be woken through the condition
# variable, where a goroutine parked on a channel is handed its batch in microseconds by Go's
# scheduler. Two ways of closing it were measured:
#
#   the writer waits awake, up to 50 us        96 · 96 %, short pauses 1 352 · 1 171   (ref 97 · 97)
#   the writer waits awake while a pass runs   95 · 95 %, short pauses 1 469 · 1 560   — nothing
#
# The second is the one without a chosen number, and it buys nothing: the pauses that matter fall
# BETWEEN passes, when a pass has stopped on the pacer or yielded to the reader and the next begins
# tens of microseconds later. Only a wait with a duration covers those, and the duration would be
# ours, not the reference's — Go spins by steal attempts, not by time. Neither is in the tree; the
# first is a product decision (one or two points of likeness for a core kept busy between batches).
#
# ⚠️ AND THE THING THAT IS LEFT IS NOT THE FEED AT ALL, which took three changes and a thread to
# establish and one line of this report to explain. The sizes gave it away:
#
#   under 300 bytes    reference 7 507 (15.6 %)      ours 1 868 (4.8 %)
#
# The reference puts three times as many small datagrams on the wire, and a small datagram at this
# MTU is an acknowledgement on its own. So its "commonest runs of two and three" are an ACK beside
# full packets rather than a short burst of data, and its higher back-to-back density comes from
# those packets filling moments when neither client is allowed to send DATA.
#
# Why it has them and this client did not is one branch in quic-go: when the send mode comes back
# pacing-limited it parks the deadline and still sends one ACK-only packet
# (vendor/quic-go/connection.go:2496-2505, `maybeSendAckOnlyPacket`). This loop returned instead —
# see tx_stop_paced in src/quic/conn.h, which counted 3 451 such stops on the run above against a
# 5 639-packet difference in small datagrams.
#
# BOTH HALVES OF THAT ARE NOW IMPLEMENTED, AND NEITHER MOVED THIS STAND. ngtcp2 had the writer all
# along — conn_write_ack_pkt, reached from the branch its own pacer guards, which patch 0009 made
# unreachable; patch 0010 exposes it. And the reason the reference gets so many more chances to use
# it is not a trigger but its loop: it yields to the reader after every batch and re-enters the send
# decision from the top (vendor/quic-go/connection.go:2622-2628, 2683-2689), which this loop now does as well
# (rx_waiting, src/quic/conn.c). Five runs on 20 September, 25 ms each way, no loss, two with the
# reader-first rule absent and three with it:
#
#                   back-to-back      under 300 B         datagrams       bytes          mean
#   ours, without   87 · 88 %         3.2 · 2.1 %         36 990-37 150   51.8 MB        1393-1399
#   ours, with      86 · 90 · 87 %    1.4 · 2.7 · 1.8 %   36 339-38 532   51.5-52.9 MB   1373-1417
#   reference       93 · 94 · 93 · 93 · 94 %   7.5-10.4 %  41 764-44 223  53.3-55.4 MB   1253-1293
#
# ⚠️ READ THE LAST ROW FIRST. The reference is the steady one — five runs inside a point of each
# other — and this client is what swings, three points either way with the same binary. Against that
# swing neither change is visible, and saying otherwise from one run would be reading noise.
#
# ⚠️ WHAT STOOD HERE READ THE SYMMETRIC TRANSFER AS "THE REFERENCE SENDS MORE PACKETS, EACH
# SMALLER" — 3-7 % more datagrams at a mean 100-160 bytes smaller — and called the density partly a
# restatement of that. A one-way measurement later showed those extra small datagrams were its
# acknowledgements of the return stream; see "AND THEN ONE MEASUREMENT OVERTURNED" above. The
# middle-sized datagrams below are a separate matter, and they held up.
#
# ⚠️ AND THAT ONE IS NOW ANSWERED, WITH A NUMBER THAT WAS PREDICTED BEFORE IT WAS MEASURED. The
# reference's middle-sized datagrams are not a choice its transport makes; they are the seam between
# two libraries:
#
#   - hysteria relays a forwarded TCP connection with plain io.Copy, and io.Copy with no WriterTo
#     or ReaderFrom to use copies through a 32 KB buffer
#     (vendor/hysteria/app/internal/forwarding/tcp.go:54-58);
#   - quic-go's stream holds exactly ONE of those writes at a time — `s.dataForWriting = p`, and the
#     writing goroutine then blocks on s.writeChan until the packer has drained it
#     (vendor/quic-go/send_stream.go:249-322). Only once the remainder fits MaxPacketBufferSize
#     (1452 bytes) is it copied into s.nextFrame and Write returns
#     (vendor/quic-go/send_stream.go:342-351, canBufferStreamFrame).
#
# So every 32 KB of payload ends in a remainder of about 750 bytes — 32768 is 23.5 packets' worth of
# stream data — and the packer puts that remainder on the wire as a short datagram before the next
# 32 KB has been read off the socket. One short datagram per 32 KB, whatever the path does.
#
# Predicted, then measured, both on 20 September:
#
#   3 x 16 MB up  =  48 MB / 32 KB  =  1 536 predicted     1 585 · 1 628 · 1 601 · 1 597 · 1 624
#   3 x  8 MB up  =  24 MB / 32 KB  =    768 predicted                                       790
#
# Five runs at one size and one at half of it, and the count halves with the payload. It is not a
# property of the congestion controller, the pacer, the ACK path or the MTU. It is the buffer size
# of io.Copy.
#
# THIS CLIENT HAS NO SUCH SEAM. The tunnel hands the uplink to ngtcp2 as a continuous queue held by
# pointer (src/quic/txbuf.h), so there is no 32 KB boundary to end a packet on and our middle-sized
# count is whatever happens to fall out — 74 · 429 · 106 · 1 124 · 401 over the same five runs, with
# no relation to the payload. Our datagrams are fuller and fewer, which is better engineering and a
# different shape on the wire, and a profiler counting packet sizes can tell the two apart from that
# alone.
#
# IMPLEMENTED ON 20 SEPTEMBER, ON THE PRODUCT'S OWN DECISION. The rule is LC_QTX_WRITE in
# src/quic/conn.h, and lc_qconn_tcp_send records the two wrong forms of it that were measured first,
# one of which cost an order of magnitude of speed. What this stand says now — two runs at 16 MB and
# one at 8 MB, against the five runs above:
#
#                   300-1000 B      under 300 B     datagrams       mean        round trip
#   ours, before    74 · 429 · 106 · 1 124 · 401    36 339-38 532   1373-1417   176-482 Mbit/s
#   ours, after     2 456 · 2 457   4.8 · 5.0 %     39 442-39 734   1307-1308   244-526 Mbit/s
#   reference       1 641 · 1 557   11.4 · 15.9 %   45 625-45 652   1179-1240   310-405 Mbit/s
#
# The seam is there and it has the reference's period: at half the payload ours falls 2 456 -> 1 098
# and the reference's 1 641 -> 868. The 3.7 % more datagrams were not paid for in throughput — this
# client is FASTER than the reference on this path, before and after.
#
# ⚠️ AND IT OVERSHOOTS BY HALF, 2 456 against 1 641, which is worth writing down because the extra
# ones are NOT the seam. They are this client running dry BETWEEN seams: 5 345 of 9 213 passes in the
# run above ended with nothing left to write, because the staging queue is UP_QUEUE_SIZE, 18 693
# bytes, refilled once per turn, where the reference's io.Copy goroutine refills continuously. That
# is the same tx_stop_dry the counters have shown all along, and it is what is left of the shape
# difference — not the pacer, not the acknowledgement path and now not the seam either.
#
# ⚠️ THE TRAP THAT COST A RUN: the relay prints its report on a timer, and three transfers can begin
# and end between two ticks. Read on the tick that happened to be there, the shape covered a tenth
# of the traffic and looked like a tenfold difference in what the two clients send. The report is
# now printed every second and the stand waits for a fresh one.
#
# Run from the repository root:
#
#	sh test/hystand/loss.sh              # 25 ms one way, 1% loss each way
#	LOSS=0.03 DELAY=50ms sh test/hystand/loss.sh   # loss is a probability, delay is one way
set -e

IMG=lc-build:local
NET=lcnet
OUT=build-stand
SIZE=${SIZE:-16777216}
# ONE DIRECTION INSTEAD OF A ROUND TRIP, with SINK=1. The far end becomes the port that answers
# nothing (test/hystand/echo), so the tunnel carries the upload alone and a client's outgoing
# datagrams are its own data rather than a mixture of data and acknowledgements for the return
# stream. That separation is the only way to ask what the small datagrams in the shape report
# actually are — see the paragraph on density above.
SINK=${SINK:-0}
if [ "$SINK" = 1 ]; then TARGET=127.0.0.1:9001; ARG=sink; else TARGET=127.0.0.1:9000; ARG=; fi
DELAY=${DELAY:-25ms}
LOSS=${LOSS:-0.01}
# THE REFERENCE ON PLAIN GO, by default, and with it ChaCha20 on both sides. On this x86 machine Go
# would use AES-NI and SSE/AVX assembly for the AEAD, while this client runs the portable code it
# runs on the router, where neither exists — so comparing the two send loops here also compared two
# ciphers, and for a day that was taken for the answer (see the note on the second party above).
# Go's own switch turns its extensions off: GODEBUG=cpu.all=off, read by internal/cpu and by
# x/sys/cpu. On the server it also makes crypto/tls prefer ChaCha20 (the toolchain's copy of
# the code at vendor/utls/handshake_server_tls13.go:180-182), so both clients are given ChaCha20,
# as on the router — ours says so in its log.
# Our client is passed the same variable and ignores it. GENERIC=0 gives the machine's crypto back.
GENERIC=${GENERIC:-1}
if [ "$GENERIC" = 1 ]; then GODEBUG_ARG="-e GODEBUG=cpu.all=off"; else GODEBUG_ARG=""; fi

W=$(pwd)
if WW=$(pwd -W 2>/dev/null) && [ -n "$WW" ]; then W=$WW; fi
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null

docker run -i --rm -v "$W:/w" -v hy-gocache:/root/.cache/go-build -v hy-gomod:/go/pkg/mod -w /w "$IMG" sh -s <<SH
set -e
cd /w
mkdir -p $OUT
sh test/hystand/build-reference.sh /w/$OUT
cd /w/test/hystand/impair && go build -o /w/$OUT/impair .
cd /w/test/hystand/echo && go build -o /w/$OUT/echo-srv .
cd /w/test/hystand/load && go build -o /w/$OUT/load-cli .
cd /w
[ -f $OUT/cert.pem ] || {
	openssl req -x509 -newkey rsa:2048 -nodes -keyout $OUT/key.pem -out $OUT/cert.pem \
	    -days 2 -subj '/CN=www.avito.ru' -addext 'subjectAltName=DNS:www.avito.ru' 2>/dev/null
	openssl x509 -in $OUT/cert.pem -outform der | sha256sum | cut -d' ' -f1 > $OUT/pin.txt
}
make -s BUILD=$OUT/lc $OUT/lc/lc-tunnel
SH

cat > "$OUT/server.yaml" <<YAML
listen: :4443
tls:
  cert: /w/$OUT/cert.pem
  key: /w/$OUT/key.pem
auth:
  type: password
  password: standpass
YAML

cat > "$OUT/refcli.yaml" <<YAML
server: loss-net:4443
auth: standpass
tls:
  sni: www.avito.ru
  insecure: true
tcpForwarding:
  - listen: 127.0.0.1:1080
    remote: $TARGET
YAML

PIN=$(cat "$OUT/pin.txt")
docker rm -f loss-srv loss-cli loss-net >/dev/null 2>&1 || true
trap 'docker rm -f loss-srv loss-cli loss-net >/dev/null 2>&1 || true' EXIT

docker run -d --name loss-srv --network "$NET" $GODEBUG_ARG -v "$W:/w" -w /w "$IMG" \
	sh -c "/w/$OUT/echo-srv & exec /w/$OUT/ref-hysteria server -c /w/$OUT/server.yaml" >/dev/null

# The impaired path, in a container of its own so that both clients reach the node through it and
# neither can tell it from the node. It is restarted for each client, because it also measures the
# SHAPE the client sends in — the gaps between its datagrams — and two clients through one relay
# would be one shape made of both.
start_relay() {
	docker rm -f loss-net >/dev/null 2>&1 || true
	docker run -d --name loss-net --network "$NET" -v "$W:/w" -w /w "$IMG" \
		sh -c "exec /w/$OUT/impair -listen :4443 -remote loss-srv:4443 -loss ${LOSS%\%} -delay $DELAY -shape $1" >/dev/null
	sleep 2
}

start_relay startup

# One client at a time in a container of its own: a client is started once per setting and torn down,
# because a fresh connection is what the loss is being measured against.
run_client() {
	who=$1
	cmd=$2
	start_relay "$who"
	docker rm -f loss-cli >/dev/null 2>&1 || true
	docker run -d --name loss-cli --network "$NET" $GODEBUG_ARG -e HYSTERIA_BBR_DEBUG="${HYSTERIA_BBR_DEBUG:-}" -v "$W:/w" -w /w "$IMG" \
		sh -c "$cmd" >/dev/null

	# Readiness is asked with the loader itself — bytes through the tunnel — because it is the one
	# probe that works the same for both clients and proves the path rather than the socket.
	#
	# ⚠️ IN SINK MODE IT HAS TO CARRY A MEGABYTE AND SAY `sink`, and getting either wrong costs a
	# whole run: the sink answers once per megabyte, so a kilobyte is answered by nothing, and a
	# probe that waits for an echo from a port which never echoes waits until the sixty tries are
	# gone. Both were got wrong in turn, and both look identical from outside — "never carried a
	# byte" — while the client in the log is up and listening.
	if [ "$SINK" = 1 ]; then PROBE=1048576; else PROBE=1024; fi
	n=0
	until docker exec loss-cli "/w/$OUT/load-cli" 127.0.0.1:1080 "$PROBE" $ARG >/dev/null 2>&1; do
		n=$((n + 1))
		[ $n -le 60 ] || { echo "  $who: never carried a byte"; docker logs loss-cli 2>&1 | tail -3; return 1; }
		sleep 1
	done
	# The first transfer through a fresh connection includes the handshake; it is reported like the
	# others rather than dropped, because the reference pays it too.
	for i in 1 2 3; do
		printf '  %-10s ' "$who"
		docker exec loss-cli "/w/$OUT/load-cli" 127.0.0.1:1080 "$SIZE" $ARG 2>&1 | tail -1
	done

	# The shape the client sent in, read off the relay both clients pass through: gaps between its
	# datagrams, and the runs that arrived together. This is what a path sees of a sender without
	# decrypting anything, and it is the half of "sends like the reference" that a throughput number
	# cannot answer.
	# A fresh report, not the one the last tick happened to leave: the relay prints every
	# second and three transfers can begin and end between two of them, which is how the first
	# version of this read a tenth of the traffic and called it the shape.
	sleep 2
	echo "  --- $who, shape on the wire"
	# Ten: five lines for what the client sent, then five for what the node sent back to it.
	docker logs loss-net 2>&1 | grep -aE "^shape " | tail -10 | sed "s/^/    /"

	# AND, FOR OURS, THE SAME SHAPE ASKED FROM THE INSIDE: the relay says how the datagrams arrived,
	# this says what the loop was doing when it produced them. The three numbers are explained at
	# their declaration in src/quic/conn.h. The reference has no such counter and is not asked for
	# one, and this path — where a window's worth is actually outstanding — is the one they answer
	# differently from run.sh's.
	if [ "$who" = "ours" ]; then
		docker kill --signal=USR1 loss-cli >/dev/null 2>&1 || true
		sleep 1
		docker logs loss-cli 2>&1 | grep -aE "chunks in|write loop:|replaced connection" | tail -3 | sed "s/^/    /"
	fi

	# The phases the controller went through, when both are asked for them: the reference prints
	# them under HYSTERIA_BBR_DEBUG, and this client's port of it prints the same lines.
	if [ -n "${HYSTERIA_BBR_DEBUG:-}" ]; then
		echo "  --- $who, phases"
		docker logs loss-cli 2>&1 | grep -a BBRSender | head -14 | sed "s/^/    /"
	fi
}

echo "=== $DELAY one way, loss $LOSS each way, $((SIZE / 1048576)) MB $([ "$SINK" = 1 ] && echo 'up only' || echo 'up and back'), three times each$([ "$GENERIC" = 1 ] && echo ', reference on plain Go')"
run_client ours "exec /w/$OUT/lc/lc-tunnel -H loss-net 4443 www.avito.ru standpass - 1080 -t $TARGET -p $PIN"
run_client reference "exec /w/$OUT/ref-hysteria client -c /w/$OUT/refcli.yaml"
