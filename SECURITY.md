# Security policy

## Supported versions

Until 1.0 only the latest release and `main` get fixes. There are no backports to older 0.x
releases; the fix ships in the next release, and routers are expected to update to it.

| Version | Supported |
|---|---|
| `main` | yes |
| latest 0.x release | yes |
| older releases | no |

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private reporting: go to the repository's Security tab
and press "Report a vulnerability", or open
<https://github.com/socketboi/lite-client/security/advisories/new> directly. Only the maintainer
can see the report, and the discussion and the fix stay private until an advisory is published.

A useful report says:

- the version (`lc-tunnel --version` prints the `git describe` of the build) and which package,
  `lite-client` or `lite-client-hysteria`;
- the plane (REALITY or Hysteria2) and the target (for example `ramips/mt7621`) if it matters;
- what an attacker needs: a position on the path, control of the node, a LAN client, a local
  account on the router;
- how to reproduce it, and a capture or a crash trace if you have one.

Strip real credentials (UUIDs, REALITY keys, Hysteria2 passwords, node addresses) from anything you
send. If a proof of concept needs a node, describe the setup instead of sharing access to yours.

## Scope

In scope is the code in this repository:

- everything under `src/`, including the TLS, QUIC crypto and certificate code written here;
- the patches in `patches/ngtcp2/`, which change ngtcp2's behaviour inside our binary;
- the OpenWrt package in `package/`: the init script, the firewall rules it installs, and how it
  stores and reads secrets under `/etc/lite-client`.

One class of report is specific to this project. The client exists to look like its reference on
the wire. If you find a difference that lets a passive observer or an active prober tell users of
this client apart from users of Xray-core or hysteria (a fingerprint, a timing or size pattern, an
answer to a probe the reference would not give), report it privately as above. Differences that do
not identify anyone go through the public "Wire difference" issue form.

Out of scope, and better reported upstream:

- bugs in the reference implementations themselves: Xray-core, XTLS REALITY, hysteria, quic-go,
  uTLS. If our client copies the behaviour faithfully, the fix belongs there first; tell us too, so
  we can follow when the reference changes;
- bugs in libraries we build against unmodified: mbedTLS, zlib, brotli, zstd, mlkem-native,
  ngtcp2 and nghttp3 outside our patches;
- OpenWrt, its kernel and its packages;
- the server or node side, which this project does not ship.

If you are unsure whether something is ours, report it here and we will sort it out.

## What happens next

This is a small project with one maintainer, so these are targets and not guarantees:

- an acknowledgement within 7 days;
- an assessment (confirmed or not, severity, affected versions) within 14 days;
- a fix and a release as soon as one is ready, and a GitHub Security Advisory with a CVE when the
  issue warrants one.

We ask for coordinated disclosure: please give us 90 days from the report, or until a fixed release
is out if that comes first, before publishing details. If the issue is already being exploited, say
so and we will move faster. Reporters are credited in the advisory unless they ask not to be.
