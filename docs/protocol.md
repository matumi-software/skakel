# Skakel protocol

**Draft.** This is version 0. It describes what Koppel 0.1 does on the wire today, taken from
Koppel's code and `docs/architecture.md` at commit `7136628`. Nothing here is new yet. Version 1
is what Skakel will ship, and "Open for version 1" at the end lists what must be decided before
then.

## Roles

- A **server** offers something (devices, ports, data) and decides who may use it.
- A **client** finds servers, pairs with them and uses what they offer.
- One machine may be both.

## Ports

One port number carries everything between machines, 5240 unless changed:

| Port | What |
|---|---|
| TCP 5240, HTTPS | Token endpoint, pairing, the remote REST API, the control hub and the data streams |
| UDP 5240 | Discovery probes and answers |

The server's certificate is self-signed. Clients pin its SHA-256 fingerprint and trust nothing
else (see "Certificates").

## Discovery

1. Every ten seconds a client broadcasts a probe to UDP 5240 on each IPv4 network it is on.
2. The probe is exactly 512 bytes: the line `KOPPEL-DISCOVER/1\n`, then zero padding.
3. A server answers only a probe of at least 512 bytes that starts with that line, and never with
   more bytes than the probe had, so it cannot be used to multiply traffic.
4. The answer is the line `KOPPEL-SERVER/1\n` followed by JSON:

   ```json
   { "name": "pi-lab", "port": 5240, "fingerprint": "EF:8E:...:29", "version": "0.1.0" }
   ```

5. The client reaches the server at the address the answer came from.

Client limits: a fingerprint of exactly 64 hex digits, a name of at most 63 characters, a version of
at most 32; anything else is dropped. At most 64 entries, at most 8 from one address. An entry that
misses three probes in a row (35 seconds) expires.

Broadcasts stay on the local network. A server elsewhere is entered by address. IPv6-only networks
are not covered.

## Pairing

A client gets its credentials by pairing. A person compares a six-digit code shown on the client
with the one they type on the server. All calls go over HTTPS, pinned to the fingerprint from
discovery, with no token.

1. The client picks a random 32-byte nonce (base64url) and sends a commitment, the uppercase hex
   SHA-256 of the nonce:

   `POST /api/pair` with `{ "clientName": "...", "commitment": "<64 hex>" }`

   The server answers `{ "requestId", "serverNonce", "expiresAt", "pollToken" }`. Only the opener
   sees the poll token.
2. The client reveals its nonce: `POST /api/pair/{requestId}/reveal` with `{ "clientNonce": "..." }`.
   The server checks it against the commitment.
3. Both ends derive the code:

   ```
   hex   = the fingerprint's hex digits, uppercase, no separators
   hash  = SHA-256( UTF-8( "koppel-pair-v1|" + hex + "|" + clientNonce + "|" + serverNonce ) )
   code  = (first 4 bytes of hash as a big-endian uint32) mod 1,000,000, as 6 digits
   ```

4. The person types the code on the server. A match registers the client.
5. The client polls `GET /api/pair/{requestId}` with header `X-Pair-Token: <pollToken>` and gets
   the state, and once approved, its client ID and secret. `DELETE` on the same path withdraws.

A man in the middle has its own certificate and has to fix each nonce before seeing the other
side's, so it cannot make the two codes match. Server limits: 60 opens per 5 minutes in total and 5
per address (an IPv4 address or an IPv6 /64), at most 3 open requests per address, at most 10
waiting requests, three wrong codes refuse a request, requests expire after five minutes.

## Tokens

- OAuth 2.0 client credentials at `POST /connect/token`, HTTPS only.
- Access tokens last 30 minutes and are signed with an RSA key whose key id is in the token header.
- Each registered client has a **generation**, carried in its tokens as the claim
  `koppel_generation`. Rotating the client's secret or revoking it raises or ends the generation,
  and every token, hub connection and data stream from an older generation is refused or ended at
  once.
- `GET /api/remote/hello` with a token answers `{ "server", "clientId" }`. Without a token it
  answers 401, which still proves the server holds the pinned certificate (used when following a
  server that moved).

## Certificates

The server's certificate lasts ten years. Replacing it is a handover, so pinned clients are not
cut off:

1. The server prepares the next certificate and keeps presenting the current one.
2. It sends the current and the next fingerprint over the control hub (`CertificatesChanged`).
   The client stores the next one as a second trusted fingerprint and answers
   `NextCertificateReceived(fingerprint)`.
3. The server switches. Clients make the next fingerprint their pinned one.

A client that was offline the whole time sees a certificate it does not know and must pair again.

## Control hub

SignalR at `/api/hubs/remote`, HTTPS, bearer token, pinned certificate. The connection closes when
the token expires; the client opens a new one 30 seconds before that, with a fresh token.

| Direction | Message | What |
|---|---|---|
| Server to client | `CertificatesChanged { fingerprint, nextFingerprint }` | On connect and on every change |
| Server to client | `DevicesChanged { devices }` | Koppel's shared USB devices, on connect and on every change |
| Client to server | `NextCertificateReceived(fingerprint)` | The client stored the next certificate |

`DevicesChanged` is Koppel's, not Skakel's. Version 1 separates the transport's messages from an
app's (see below).

## Data streams

One WebSocket per stream on the HTTPS port, with the bearer token and the pinned certificate.
Binary frames only. Both ends ping every 15 seconds and give up after 30 without an answer. A
stream ends when the client is revoked or rotated, or when the server stops serving it.

Koppel 0.1 has one stream type, `/api/remote/usb`, which carries plain USB/IP (the Linux kernel's
format) inside the WebSocket.

## Open for version 1

- **Version in the handshake.** A client and a server must agree on a protocol version before
  anything else, on the hub and on every stream, and refuse each other in words a person can read
  when they cannot.
- **Which app a server is.** Discovery and the hub must say which app and which capabilities a
  server offers, so an app lists only the servers it can use.
- **Names.** `KOPPEL-DISCOVER/1`, `KOPPEL-SERVER/1`, `koppel-pair-v1` and `koppel_generation`
  name Koppel. Renaming them breaks Koppel 0.1 clients, so either keep them as they are or let a
  server answer both for a while.
- **Transport messages and app messages.** The hub carries both today. Version 1 gives an app its
  own messages beside Skakel's, without the two sharing names.
- **Stream types.** A general way to open a stream of a named type (`usb`, `serial`, and whatever
  an app adds) with its own parameters, instead of one path per type.
- **Serial streams** (Koppel #46): line settings (baud, data bits, parity, stop bits, flow control),
  modem lines (DTR and RTS from the client; CTS, DSR, DCD and RI back) and break as control frames
  beside the data. The server applies flow control on the real port, because XON/XOFF and RTS/CTS
  cannot make a round trip over the network in time.
- **More than one server per client** (Koppel #21).
- **IPv6** discovery.
