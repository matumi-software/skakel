# Enrolling a client: a code or a key

Status: an addition to Skakel protocol 3, summarised in "Enrolling with a code or a key" in
`protocol.md`. This file is the specification: the messages, the transcripts and the limits.

## What a person sees

- On the **server**, one button shows a **pairing code**: eight digits, good for 60 seconds, used
  once. The server also keeps a **server key**, a long secret the person copies to another computer
  once and can rotate at any time.
- On the **client**, a person adds a server by typing its address and **either** the code **or**
  the key. There is nothing to compare, and nothing to approve on the server. A client may add
  any number of servers.
- Both end with what pairing ends with today: a client ID and secret for that server, and the
  server's fingerprint pinned.

## Why not the code we have

Today's pairing derives a code from both ends' nonces and the certificate, shows it on the client
and has a person type it on the server (see "Pairing" in `protocol.md`). The code only exists once
the client has started, so it cannot be shown first. The new flow shows the code first, so the
code is a password that both ends know before anything is sent.

A short password must not be sent as proof in the clear: anyone in the middle could record a proof
made from an eight-digit code and find the code offline in seconds, then enrol in the client's
place. So the code is used in a **password-authenticated key exchange** (SPAKE2), where a recorded
exchange tells an attacker nothing about the code. Each wrong confirmation is one online guess, and
the server counts them.

## The code

The server shows `code`, 8 random digits, and keeps it for `ttl` (the app chooses: at least 30
seconds, at most 5 minutes, 60 by default). Showing a new code replaces the old one.

1. The client opens a TLS connection to the address and **reads the fingerprint `F` of the
   certificate it is shown**. It trusts nothing yet.
2. `POST /skakel/v3/enroll/code` with `{ "clientName", "pake" }`: `pake` is the client's SPAKE2
   message for the password `code`, base64url. The server answers `{ "enrollId", "pake", "expiresAt" }`
   with its own message. A server with no open code answers 403 with the reason `enrolment-closed`.
3. Both ends derive the session key `K`, and from it two confirmation keys with HKDF, `kc` and `ks`.
   The transcript is

   ```
   T = lp("skakel-enroll-code-v1") + lp(F) + lp(UTF-8(clientName)) + lp(clientPake) + lp(serverPake)
   ```

   where `F` is the 32 bytes of the certificate the **client saw**, and the server puts in its own.
4. `POST /skakel/v3/enroll/code/{enrollId}/confirm` with `{ "mac": HMAC(kc, "c" + T) }`. The server
   checks it. A match answers `{ "mac": HMAC(ks, "s" + T), "clientId", "clientSecret" }`, once, and
   the code is spent. The client checks the server's `mac` **before it pins `F`**, so it knows the
   server had the code and saw the same certificate.
5. A wrong `mac` counts as one wrong code. Three wrong confirmations, expiry or a success spend the
   code; the next call gets 404.

A man in the middle presents its own certificate, so the `F` on each side differs and the MACs
cannot match without the code, and the exchange gives no way to test a guess offline. He has one
guess in a hundred million per confirmation, three confirmations per code.

## The key

The server keeps one **server key** at a time: 32 random bytes `s` and the first 16 bytes `t` of its
certificate's SHA-256 fingerprint, written as `kp1_` and the base32 of `s + t` (Crockford alphabet,
no padding, 77 characters). The key never travels: a client proves it holds it.

1. The client reads the fingerprint `F` the server presents and **refuses** if its first 16 bytes
   are not `t`. That is the pin, and it comes with the key.
2. `POST /skakel/v3/enroll/key` with `{ "clientName", "nonce", "mac" }`, where
   `mac = HMAC(s, lp("skakel-enroll-key-v1") + lp(F) + lp(UTF-8(clientName)) + lp(nonce))` and
   `nonce` is 32 random bytes as base64url. The server verifies it with its own fingerprint and
   answers `{ "mac": HMAC(s, "s" + the same), "clientId", "clientSecret" }`. The client checks the
   server's `mac`, then pins `F`.

The key is 256 bits, so guessing is out of reach; the limit below only stops hammering. It stays
valid until rotated, so a person can add computers any time without a code. **Rotating** makes a new
key and spends the old one. Clients already enrolled keep working: their own secrets are theirs.

## What the server records and offers

- Each registered client records **how it was linked**: `code` or `key` (the old pairing records
  `pairing`). Apps list it.
- `SkakelServer` gains: `open_enrollment_code(ttl) -> { code, expires_at }`,
  `close_enrollment_code()`, `enrollment_key() -> String`, `rotate_enrollment_key() -> String`,
  and an event when a client enrols, with its method. Rotating a client's secret and removing a
  client are what they are now.
- `GET /skakel/info` lists `"enroll": ["code", "key"]` when the server does it, so a client can say
  "this server cannot be added with a code, update it" in words.

## What the client offers

`SkakelClient::enroll_with_code(address, code, name)` and `enroll_with_key(address, key, name)`
return the credentials and the fingerprint to pin, or a reason a person can act on: closed,
expired, wrong code, wrong key ("this key is for another server"), not a Skakel server, a
protocol mismatch. Adding several servers is the app's: each is its own address, client ID and secret
(the client already supports one set per server).

## Limits

The per-address limits of "Pairing" apply to the new paths (5 starts per 5 minutes per address, 120
calls a minute in all). Three wrong confirmations spend a code. For the key, 10 wrong proofs from one
address in a minute turn that address away for the rest of the minute. Bodies are capped at 4 KiB.
Plain HTTP gets 400.

## Compatibility

Everything is new paths and a new `info` field, so it is an addition inside protocol 3: a server or
client that does not know it is unaffected, and today's pairing stays. Tweeling can ignore it. The
protocol version does not change. The wire descriptor golden and the pinned bytes get new tests for
the transcript and the key format.

## Open points

- SPAKE2 (the RustCrypto `spake2` crate, MIT or Apache-2.0) or CPace. Either fits; the licence and
  maintenance of the chosen crate are checked with `cargo metadata` and `cargo deny check` before it
  goes in, as `parts.md` requires.
- Whether Koppel keeps today's pairing in its UI. This proposal assumes it does not, and Skakel keeps
  it for other apps.
