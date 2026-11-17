# Supporting lite-client

Bug reports and questions go to the issue tracker. This page is about money.

lite-client is written and tested by one person. Donations pay for:

- Test routers. A release goes out only after it has run on real hardware. Right now that is a
  Xiaomi Mi Router 4A Gigabit (MT7621, mipsel_24kc) and a Xiaomi AX3000T (MT7981, aarch64).
  Other small routers people ask about get bought when there is money for them.
- Test servers. A couple of small VPS in different countries that run the reference servers,
  Xray-core and apernet/hysteria, which every change is checked against.
- Time spent on this instead of paid work.

Donations are gifts. They don't buy support, priority on issues, or a say in what gets merged.

## Crypto

Addresses for USDT on TRON (TRC-20), TON and Monero are not published yet. They will appear here
and in `docs/donate.txt`, signed as described below, and nowhere else first.

When sending USDT, pick the TRON network in your wallet or exchange. TRON and TON are public
ledgers: anyone can see what an address has received and from where. If you don't want your
donation to be visible, use Monero.

There is no card or PayPal option. Those platforms need a legal name and a bank account, and this
project is published under a pseudonym.

## Checking the addresses

Forks of network tools sometimes swap the donation addresses for their own. The addresses will be
in `docs/donate.txt`, signed with an SSH key that belongs to the `socketboi` GitHub account. To
check the signature:

```sh
curl -sL https://github.com/socketboi.keys \
  | sed 's/^/socketboi namespaces="file" /' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I socketboi -n file \
  -s docs/donate.txt.sig < docs/donate.txt
```

It should print `Good "file" signature for socketboi`. Addresses posted anywhere else, in chats,
issues or forks, are not mine unless they are in this file and the signature checks out. If they ever
change, the change will be in a commit to `donate.txt` and in the release notes.

## Paid work

If your company runs lite-client and wants a specific feature or a port to a particular router, open
an issue. Payment for that is in crypto as well.

## Not money

Test reports help about as much. If you run lite-client on a router that isn't listed above, an
issue with the model, OpenWrt version, package version and a throughput number is useful even when
everything works.
