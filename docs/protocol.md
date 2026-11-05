# Skakel protocol

Version 1. This is the contract between Skakel clients and servers, and between apps built on them.
A change to what goes over the wire changes this file in the same pull request.

Version 0 is what Koppel 0.1.0 speaks. Version 1 keeps its design and changes its names and paths;
the two do not talk to each other (see "Changes from version 0").

## Roles

- A **server** offers something (devices, ports, data) and decides who may use it.
- A **client** finds servers, pairs with them and uses what they offer.
- An **app** is the program on top, such as Koppel. Each server belongs to one app. One machine may
  run a client and a server, and several apps.

## Versions

- Every path a client calls, except the info endpoint and discovery, carries the protocol version:
  `/skakel/v1/...`.
- Before anything else, a client learns which versions a server speaks, from discovery or from
  `GET /skakel/info`, and picks the highest one both speak.
- When there is none, the client says so in words a person can act on, naming both sides' versions,
  such as "This server speaks Skakel 2 and this app speaks Skakel 1. Update the app." It never
  tries a path it already knows the server does not serve.
- A server keeps every version it lists working until a release that says otherwise.

## Ports

An app picks its own port number, and uses it for both TCP and UDP. Koppel's is 5240. Two apps on
one machine use two port numbers.

| Port | What |
|---|---|
| TCP, HTTPS | Info, pairing, tokens, the app's REST API, the hub and the streams |
| UDP, same number | Discovery |

The server's certificate is self-signed. Clients pin its SHA-256 fingerprint and trust nothing else
(see "Certificates"). A fingerprint is written as 32 hex pairs separated by colons and compares by
its hex digits alone.

## Discovery

1. A client broadcasts a probe every ten seconds to its app's port, on each IPv4 network it is on.
2. A probe is exactly 512 bytes: the line `SKAKEL-DISCOVER/1\n`, then zero padding.
3. A server answers only a probe of at least 512 bytes that starts with that line, and never with
   more bytes than the probe had, so it cannot be used to multiply traffic.
4. The answer goes to the address and port the probe came from: the line `SKAKEL-SERVER/1\n`, then
   JSON (UTF-8, camelCase):

   ```json
   {
     "name": "pi-lab",
     "port": 5240,
     "fingerprint": "EF:8E:...:29",
     "app": { "id": "koppel", "version": "0.1.1" },
     "versions": [1]
   }
   ```

5. The client reaches the server at the address the answer came from, on `port`.

The `/1` in the two lines is the discovery format's own version. It changes only if the packet
layout does.

**Limits a client applies:** a fingerprint of exactly 64 hex digits; a name of at most 63
characters; an app id of at most 32 characters from `a-z`, `0-9` and `-`; an app version of at most
32 characters; at most 8 versions. Anything else drops the answer. A client keeps at most 64
entries, at most 8 from one address, and when full drops the stalest entry of the address that
holds the most. An entry that misses three probes in a row (35 seconds) expires. An app shows only
the servers whose app id it can use.

Broadcasts stay on the local network: a server elsewhere is entered by address. IPv6 discovery is
not in version 1.

## Info

`GET /skakel/info`, HTTPS, no token. Unversioned, so a client of any version can read it.

```json
{
  "name": "pi-lab",
  "app": { "id": "koppel", "version": "0.1.1" },
  "versions": [1]
}
```

Any answer over a connection pinned to a fingerprint proves the server holds that certificate. A
client that follows a server to a new address checks it this way before it moves (see "Following a
server").

## Pairing

A client gets its credentials by pairing. A person compares a six-digit code shown on the client
with the one they type on the server. Every call goes over HTTPS pinned to the fingerprint from
discovery, with no token.

1. The client picks a random 32-byte nonce, written as base64url, and sends a commitment, the
   uppercase hex SHA-256 of the nonce's UTF-8 bytes:

   `POST /skakel/v1/pair` with `{ "clientName": "...", "commitment": "<64 hex digits>" }`

   `clientName` is 1 to 80 characters after trimming. The server answers
   `{ "requestId", "serverNonce", "expiresAt", "pollToken" }`. Only the opener gets the poll token.
2. The client reveals its nonce: `POST /skakel/v1/pair/{requestId}/reveal` with
   `{ "clientNonce": "..." }`. The server checks it against the commitment and answers 204, or 404.
3. Both ends derive the code:

   ```
   hex   = the fingerprint's hex digits, uppercase, no separators
   hash  = SHA-256( UTF-8( "skakel-pair-v1|" + hex + "|" + clientNonce + "|" + serverNonce ) )
   code  = (the first 4 bytes of hash as a big-endian uint32) mod 1,000,000, as 6 digits
   ```

4. The person types the code on the server, in the app's own screen. A match registers the client.
5. The client polls `GET /skakel/v1/pair/{requestId}` with the header `X-Pair-Token: <pollToken>`
   and gets `{ "state" }`, and once approved `{ "state", "clientId", "clientSecret" }`. `DELETE` on
   the same path, with the same header, withdraws the request. The token is compared in constant
   time.

A man in the middle has its own certificate and has to fix each nonce before seeing the other
side's, so it cannot make the two codes match.

**Limits a server applies:** 60 opens per 5 minutes in total and 5 per address (an IPv4 address or
an IPv6 /64), never refunded; at most 3 open requests per address; at most 10 requests that have
revealed their nonce; a request that has not revealed within 30 seconds is dropped; requests expire
after five minutes; three wrong codes refuse a request. An open that goes over a limit gets 429.

A client paired with several servers holds one client ID and secret for each.

## Tokens

- OAuth 2.0 client credentials at `POST /skakel/v1/token`, HTTPS only.
- Access tokens last 30 minutes and are signed with an RSA key whose key id is in the token header.
  Clients do not read what is inside a token.
- Each registered client has a **generation**, which the server writes into its tokens as the claim
  `skakel_generation`. Rotating a client's secret raises its generation, and revoking a client
  removes it. Every token, hub connection and stream from an older generation, or from a removed
  client, is refused or ended at once.
- `GET /skakel/v1/hello` with a token answers `{ "server", "clientId" }`. An app's Test button uses
  it to check credentials.

**Limits a server applies:** 60 token requests per minute per address. A failed request gets the
OAuth error, never the reason the secret was wrong.

## Certificates

A server's certificate lasts ten years. Replacing it is a handover, so pinned clients are not cut
off:

1. The server prepares the next certificate and goes on presenting the current one.
2. Over the hub it sends `SkakelCertificates { fingerprint, nextFingerprint }`. The client stores
   the next fingerprint as a second trusted one and calls
   `SkakelNextCertificateReceived(fingerprint)`, so the server can show who has it.
3. The server switches, and says so with another `SkakelCertificates`. Clients make the next
   fingerprint their pinned one and drop the old.

Cancelling sends `SkakelCertificates` with no next fingerprint, and clients forget it. A client that
was offline for the whole handover sees a certificate it does not know and must pair again.

## Following a server

When a client cannot reach a server's saved address at all (refused, timed out, no route, a name that
no longer resolves) and discovery hears a server with the pinned fingerprint, or the next one it was
told about, at another address or port, the client checks that address with `GET /skakel/info`
pinned to those fingerprints, within 5 seconds, and moves only if that answers. A certificate that
does not match, or credentials the server refused, are not a reason to move. An address it moved to
is not moved to again for five minutes.

## Hub

One SignalR hub per server, at a path the app picks under `/skakel/v1/`, such as
`/skakel/v1/hub`. HTTPS, bearer token, pinned certificate. The server closes a connection when its
token expires; the client connects again 30 seconds before that, with a fresh token.

Skakel's own messages start with `Skakel`. Every other name belongs to the app. An app may not start
a message name with `Skakel`.

| Direction | Message | When |
|---|---|---|
| Server to client | `SkakelCertificates { fingerprint, nextFingerprint }` | On connect and whenever either changes |
| Server to client | `SkakelClosing { reason }` | Just before the server ends the client's connections and streams: `revoked`, `rotated` or `stopping` |
| Client to server | `SkakelNextCertificateReceived(fingerprint)` | The client stored the next certificate |

An app's REST endpoints sit beside the hub under paths the app picks, and take the same bearer
token.

## Streams

A stream is one WebSocket that carries one thing: a USB device, a serial port, or whatever an app
defines.

- **Opening:** a WebSocket upgrade at `/skakel/v1/streams/{type}`, with the bearer token and the
  pinned certificate. `{type}` is from `a-z`, `0-9` and `-`. What the stream is for goes in the
  query string, defined by the type.
- **Refusing:** the server checks everything before it accepts the upgrade, so a refusal is an HTTP
  answer with a problem JSON body (`application/problem+json`) whose `detail` a person can read:

  | Status | When |
  |---|---|
  | 401 | No token, an expired one, or one from an older generation |
  | 404 | The server has no such type, or no such target |
  | 409 | The target is in use; `detail` names who holds it, when the app allows that |
  | 422 | The query string is not what the type expects |

- **Frames:** binary frames carry the stream's data. Text frames carry control messages, one JSON
  object each, with an `op` field. Frames keep their order across both kinds, so a control message
  takes effect between the bytes sent before it and the bytes sent after it. A type that has no
  control messages uses binary frames only.
- **Keep-alive:** both ends send WebSocket pings every 15 seconds and give up after 30 without an
  answer.
- **Closing:** a close frame with a code a client can act on:

  | Code | Meaning |
  |---|---|
  | 1000 | Closed normally |
  | 4001 | The client was revoked |
  | 4002 | The client's secret was rotated |
  | 4003 | The server is stopping, or no longer serves this type |
  | 4004 | The target went away (unplugged, removed) |
  | 4100 to 4999 | Defined by the stream type |

Stream types used by more than one app are defined here, so apps of any licence can speak them.
A type only one app uses is defined by that app.

## The serial stream type

Type `serial`: one serial port on the server, used by one client at a time.

**Opening:** `/skakel/v1/streams/serial?port=<id>`, where `<id>` is the port's id from the app's own
list of ports. A second client gets 409.

**Data:** binary frames, the bytes as they leave and arrive at the port, with no framing of their
own. The server writes to the port only as fast as the port takes the bytes, and stops reading the
WebSocket while the port's buffer is full, so a slow port slows the client down instead of losing
bytes.

**Control, client to server:**

| `op` | Fields | What |
|---|---|---|
| `lineSettings` | `baud` (integer), `dataBits` (5 to 8), `parity` (`none`, `odd`, `even`, `mark`, `space`), `stopBits` (`1`, `1.5`, `2`), `flowControl` (`none`, `rtsCts`, `xonXoff`) | Change the port's settings. Every field is required |
| `modemLines` | `dtr`, `rts` (booleans, either may be left out) | Set the output lines |
| `break` | `on` (boolean) | Start or end a break |
| `purge` | `input`, `output` (booleans) | Throw away what is buffered on the server |

**Control, server to client:**

| `op` | Fields | What |
|---|---|---|
| `opened` | `lineSettings`, `modemStatus` | First message after the upgrade: the port as it is now |
| `lineSettings` | The fields above | The settings now on the port, after a change was applied. A client treats a change as done only when this comes back |
| `modemStatus` | `cts`, `dsr`, `dcd`, `ri` (booleans) | Whenever an input line changes |
| `error` | `code` (`unsupported`, `framing`, `parity`, `overrun`), `detail` | A change the port refused, or errors the port reported. A refused change leaves the settings as they were |

**Rules:**

- The server applies a change only after the bytes sent before it have left the port, so a program
  that changes baud between two messages works.
- **Flow control runs on the server, on the real port.** XON/XOFF and RTS/CTS have to react within a
  few characters, which a round trip over the network cannot. With `rtsCts` the server drives RTS
  itself, and `modemLines` changes to `rts` are ignored. With `xonXoff` the port's driver handles
  XON and XOFF and they do not appear in the data.
- A port the server cannot set a value on (a baud rate it does not support, `1.5` stop bits with 8
  data bits) gets an `error` with `unsupported`.

**Close codes:** 4100, the port reported a fault and was closed.

## Changes from version 0

Version 0 is Koppel 0.1.0. A version 0 client cannot talk to a version 1 server, or the other way
round: both ends update together.

| Version 0 | Version 1 |
|---|---|
| `KOPPEL-DISCOVER/1`, `KOPPEL-SERVER/1` | `SKAKEL-DISCOVER/1`, `SKAKEL-SERVER/1` |
| Discovery answer has `version` (Koppel's) | `app { id, version }` and `versions` |
| No version negotiation | Versioned paths and `GET /skakel/info` |
| `/api/pair` | `/skakel/v1/pair` |
| `/connect/token` | `/skakel/v1/token` |
| `/api/remote/hello`, also used to prove the certificate | `/skakel/v1/hello` for credentials, `/skakel/info` for the certificate |
| `koppel-pair-v1` in the code derivation | `skakel-pair-v1` |
| Claim `koppel_generation` | `skakel_generation` |
| `/api/hubs/remote`, messages `CertificatesChanged`, `NextCertificateReceived` | Hub path chosen by the app; `SkakelCertificates`, `SkakelNextCertificateReceived`, and `SkakelClosing` added |
| `/api/remote/usb` | `/skakel/v1/streams/usb`, a Koppel type |
| Close reasons only in Koppel's log | Close codes and problem JSON a client can show |

## Not in version 1

- IPv6 discovery.
- Several apps behind one port.
- Resuming a stream after the connection drops: a client opens a new one.
