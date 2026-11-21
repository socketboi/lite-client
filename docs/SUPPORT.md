# Supporting lite-client

Donations help pay for test routers, VPS instances for compatibility tests, and
maintainer time.

## Donate directly

**Donations are not open yet.** Wait for the signed address list on this page
before sending funds.

The first planned option is **USDT on TRON (TRC-20)**. Donations will go directly
to a project wallet. Each published entry will identify the asset, network and
receiving address. Use that exact network in your wallet or exchange. TRON
transfers are public.

TON and Monero will be listed when their verified receiving addresses are
available. Donations are voluntary gifts.

## Verify a published address

When donations open, the [official repository](https://github.com/socketboi/lite-client)
will publish `docs/donate.txt`, its signature, and the project's dedicated public
signer. From an official checkout, verify the list with OpenSSH:

```sh
ssh-keygen -Y verify -f docs/donation-signers -I socketboi -n lite-client-donations \
  -s docs/donate.txt.sig < docs/donate.txt
```

Copy the address from the verified file. Address changes will be published in
the repository and announced in the release notes.

## Paid work

If your company runs lite-client and wants a specific feature or a port to a
particular router, open an issue. Payment for that is in crypto as well.

## Help with testing

Reports from additional router models are welcome. Open an
[issue](https://github.com/socketboi/lite-client/issues) with the router model,
OpenWrt version, LiteClient version and a throughput result.
