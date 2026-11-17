# Disposable device integration stand

These fixtures test a temporary, uninstalled `lc-tunnel` against the pinned
Xray and Hysteria reference servers. They do not install router packages or
change firewall, routes, UCI, services, node ports or production credentials.

`server.py` runs inside a disposable, resource-limited Linux container. Mount
the fixture and operator-supplied test configuration read-only at `/fixture`;
give `/run/stand` a private writable tmpfs. Required files are `ref-xray`,
`ref-hysteria`, `xray.json`, `hysteria.json`, `cert.pem` and `key.pem`.
Use independent disposable test identities, never production trust roots.
Reference listeners use TCP 29600 and UDP 29601 on the operator-selected lab
address. The checked TCP, TLS 1.3, donor and UDP backends are loopback-only on
29602 through 29605. Control is a mode-0600 Unix socket, not a network endpoint.
`control.py ACTION PLANE` supports status, pause, resume, stop and restart;
startup/restart acknowledgements require the child to own its listening socket.

The pinned Xray freedom outbound has a default private-address guard. For this
isolated stand, explicitly allow only loopback TCP 29602/29603 and UDP 29605
in `settings.finalRules`. Leave its other rules intact. Qualify the backend
through the pinned Xray client using `reference-check.py` before testing C:
its local HTTP inbound is expected on 29610. A connected socket is insufficient.

The stream protocol starts with a network-order `!4sQQIIBB` header: `LCI1`,
upload/download lengths, their seeds, server read delay in milliseconds and
a deliberate-corruption flag. Each 32768-byte block is SHAKE256 of its
network-order `!QI` block index and seed. Both directions check every byte.
The server emits `LCOK` followed by both SHA256 digests only after both
directions finish. A successful client must validate that receipt. Limits and
intentional corruption make transport-only false positives observable.

Cross-build `udp.c` with the documented MIPS toolchain. Pass listener port and
`reality` or `hysteria`. It checks sixteen echoed datagrams, including
fragmentation/reassembly. REALITY accepts a 4096-byte payload. For the fixed
Hysteria target `127.0.0.1:29605`, the 24-byte header leaves 4072 payload bytes
inside MaxUDPSize. The fixture checks that exact boundary, the reference's
silent drop at 4073, and a seventeenth valid echo after the drop. `router.sh`
accepts an owned `/tmp/lc-integration.*` directory and a named test phase;
it runs only on the lab Mi Router 4A and enforces time, available-memory and
client-RSS limits. Required binaries are `lc-tunnel.hy0`, `lc-tunnel.hy1`,
`firefox.fpt` and `udp.mipsel`. Identities are read from mode-0600 test files.
Sampled RSS sums every client worker; it is not a precise peak measurement.

Keep host aliases, addresses, identities and the SSH orchestration in private
evidence. If SSH forwarding is needed to reach the temporary listener, isolate
load connections from control and use a separate SSH connection per load flow.
A shared duplex SSH transport can stall under load and invalidate the result.
Use a current Python for TLS backpressure: Python 3.10's asyncio TLS transport
can fail while resuming a reader after peer closure. Neither failure establishes
a LiteClient defect. This SSH path is not suitable for throughput comparisons.

Archive logs, binary hashes, reference revisions, process exits and before/after
router invariants before removing the owned temporary processes and directories.
Do not count this integration stand as paired fingerprint/G2 acceptance or an
extended soak on production traffic.
