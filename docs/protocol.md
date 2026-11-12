# Skakel protocol

Version 2. This is the contract between Skakel clients and servers, and between apps built on them.
A change to what goes over the wire changes this file in the same pull request.

The control channel and the data streams are gRPC, and their wire format is the `.proto` files in
[`src/proto/skakel/v2/`](../src/proto/skakel/v2/), from which a client or server in any language can
be generated. This file says what the messages mean and how the two ends behave.

Version 1 (Skakel 0.1.0) had a SignalR hub and WebSocket streams; version 2 keeps its discovery,
info, pairing, tokens and certificate handover, and moves the hub and the streams to gRPC. The two
do not talk to each other (see "Changes from version 1"). The server and the client crates in this
repository speak version 2; version 1's text is this file at commit `aa0399b`.

## Roles

- A **server** offers something (devices, ports, data) and decides who may use it.
- A **client** finds servers, pairs with them and uses what they offer.
- An **app** is the program on top, such as Koppel. Each server belongs to one app. One machine may
  run a client and a server, and several apps.

## Versions

- Every path a client calls, except the info endpoint and discovery, carries the protocol version:
  `/skakel/v2/...` for the HTTPS calls, and the package `skakel.v2` in the gRPC calls, such as
  `/skakel.v2.ControlService/Connect`.
- Before anything else, a client learns which versions a server speaks, from discovery or from
  `GET /skakel/info`, and picks the highest one both speak.
- When there is none, the client says so in words a person can act on, naming both sides' versions,
  such as "This server speaks Skakel 2 and this app speaks Skakel 1. Update the app." It never
  tries a path it already knows the server does not serve.
- A server keeps every version it lists working until a release that says otherwise.

A version 2 server lists `[2]`, so a version 1 client finds no version both speak and says so, as it
does today for any version it does not know. A version 2 client does the same with a version 1
server.

## Ports

An app picks its own port number, and uses it for both TCP and UDP. Koppel's is 5240. Two apps on
one machine use two port numbers.

| Port | What |
|---|---|
| TCP, HTTPS | Info, pairing, tokens and the app's own HTTPS endpoints, and gRPC: the control service, the stream service and the app's own services (see "One port for HTTPS and gRPC") |
| UDP, same number | Discovery |

The server's certificate is self-signed. Clients pin its SHA-256 fingerprint and trust nothing else
(see "Certificates"). A fingerprint is written as 32 hex pairs separated by colons and compares by
its hex digits alone.

A client connects to a server directly, never through a proxy, and reads at most 64 KB of any plain
HTTPS answer. A longer answer, like any other it cannot use, is one that "did not answer like a
Skakel server". gRPC messages have limits of their own (see "One port for HTTPS and gRPC").

## Discovery

1. A client broadcasts a probe every ten seconds to its app's port, on each IPv4 network it is on.
2. A probe is exactly 512 bytes: the line `SKAKEL-DISCOVER/1\n`, then zero padding.
3. A server answers only a probe of at least 512 bytes that starts with that line, and never with
   more bytes than the probe had, so it cannot be used to multiply traffic. A server cuts its name
   to 63 characters and its app version to 32, and shortens the name further if that is what it
   takes for the answer to fit in 512 bytes.
4. The answer goes to the address and port the probe came from: the line `SKAKEL-SERVER/1\n`, then
   JSON (UTF-8, camelCase). A probe from port 0, or from an address that is not a single host
   (unspecified, broadcast, multicast), gets no answer:

   ```json
   {
     "name": "pi-lab",
     "port": 5240,
     "fingerprint": "EF:8E:...:29",
     "app": { "id": "koppel", "version": "0.1.1" },
     "versions": [2]
   }
   ```

5. The client reaches the server at the address the answer came from, on `port`.

The `/1` in the two lines is the discovery format's own version. It changes only if the packet
layout does.

**Limits a client applies:** a fingerprint of exactly 64 hex digits; a name of at most 63
characters; an app id of at most 32 characters from `a-z`, `0-9` and `-`; an app version of at most
32 characters; at most 8 versions. Anything else drops the answer. From the name and the app
version the client takes out Unicode control and format characters and line and paragraph
separators (categories Cc, Cf, Zl and Zp), and trims them. It takes answers only within 3 seconds
of a probe it sent.

A client keeps one entry per fingerprint, address and port, so an answer that copies another
server's fingerprint sits beside it and never changes it. It keeps at most 64 entries and at most
8 from one address. When it has to make room it drops an entry from that address, or when the list
is full from the address that holds the most: the one that answered the fewest probes, then the
stalest. It never drops an entry with a fingerprint a running link has pinned; when only those are
left, the new answer is dropped. An entry that misses three probes in a row (35 seconds) expires.

A client lists one server per fingerprint: the address that answered first, on its best network,
with the other addresses that answered with the same fingerprint beside it. Anyone can copy a
fingerprint, so several addresses for one is worth showing; only a pinned connection tells which
holds the certificate. An app shows only the servers whose app id it can use.

Broadcasts stay on the local network: a server elsewhere is entered by address. IPv6 discovery is
not in version 2.

## Info

`GET /skakel/info`, HTTPS, no token. Unversioned, so a client of any version can read it.

```json
{
  "name": "pi-lab",
  "app": { "id": "koppel", "version": "0.1.1" },
  "versions": [2]
}
```

Any answer over a connection pinned to a fingerprint proves the server holds that certificate. A
client that follows a server to a new address checks it this way before it moves (see "Following a
server").

**Limits a client applies:** the same as discovery's. The name is cleaned the same way and cut to
63 characters (the server's address stands in when nothing is left); an app id that breaks the rule
or an app version over 32 characters makes the answer one the client cannot use.

## Pairing

A client gets its credentials by pairing. A person compares a six-digit code shown on the client
with the one they type on the server. Every call goes over HTTPS pinned to the fingerprint from
discovery, with no token.

1. The client picks a random 32-byte nonce, written as base64url, and sends a commitment, the
   uppercase hex SHA-256 of the nonce's UTF-8 bytes:

   `POST /skakel/v2/pair` with `{ "clientName": "...", "commitment": "<64 hex digits>" }`

   `clientName` is 1 to 80 characters once the server has taken out Unicode control and format
   characters (categories Cc and Cf: line breaks, NUL, direction overrides, zero-width characters)
   and trimmed it; that is the name it keeps. The server answers
   `{ "requestId", "serverNonce", "expiresAt", "pollToken" }`. Only the opener gets the poll token.
   A body that breaks these rules gets 400.
2. The client reveals its nonce: `POST /skakel/v2/pair/{requestId}/reveal` with
   `{ "clientNonce": "..." }`. The server checks it against the commitment and answers 204, or 404,
   or 429 when it takes no more revealed requests for now (see the limits below).
3. Both ends derive the code:

   ```
   hex   = the fingerprint's hex digits, uppercase, no separators
   hash  = SHA-256( UTF-8( "skakel-pair-v1|" + hex + "|" + clientNonce + "|" + serverNonce ) )
   code  = (the first 4 bytes of hash as a big-endian uint32) mod 1,000,000, as 6 digits
   ```

4. The person types the code on the server, in the app's own screen. A match registers the client.
5. The client polls `GET /skakel/v2/pair/{requestId}` with the header `X-Pair-Token: <pollToken>`
   and gets `{ "state" }`, and once approved `{ "state", "clientId", "clientSecret" }`. The state is
   `waiting`, `approved`, `denied` (refused on the server, or the code was wrong three times) or
   `expired`. The poll that sees `approved` carries the credentials, once; after it the request is
   gone. `DELETE` on the same path, with the same header, withdraws a waiting request and answers
   204. An unknown request or a wrong token gets 404 on both. The token is compared in constant
   time.

The `v1` in `skakel-pair-v1` is the derivation's own version, as `/1` is discovery's, and it
stays as it is in protocol version 2.

A man in the middle has its own certificate and has to fix each nonce before seeing the other
side's, so it cannot make the two codes match.

**Limits a server applies:** 5 opens per 5 minutes per address; 60 revealed requests per 5 minutes
for the whole server; neither is refunded, by withdrawing or by expiry. An open that never reveals
counts against its address but not against the server's 60. At most 3 open requests per address;
at most 10 revealed requests waiting for a person at once; at most 64 requests that have opened and
not yet revealed, for the whole server; a request that has not revealed within 30 seconds is
dropped; requests expire after five minutes; three wrong codes refuse a request. An open
or a reveal that goes over a limit gets 429. All pairing calls together, polls included, are limited
to 120 a minute per address, also answered with 429, so a client polls no more than once a second.
A revealed nonce shorter than 43 characters (the 32 bytes a client picks, as base64url) is refused
like one that does not match the commitment, with 404, so a client with a weak nonce cannot have its
commitment guessed offline. A pairing call over plain HTTP gets 400. A body over 4 KiB gets 413, or 400 when the server only
finds out while reading it, and so does a body that has not arrived in full within 10 seconds. Both of these limits apply before the server reads the request.

An address is the whole IPv4 address the call came from, an IPv4-mapped IPv6 address counted as its
IPv4 address, or the `/64` of an IPv6 address: a host on a network owns its whole `/64` and can send
from any address in it, so counting single IPv6 addresses would let one host spend every limit as
often as it likes. Every per-address limit in this document counts addresses this way. What the
server shows the app as where a request came from is still the whole address.

Many `/64`s that each open and reveal can still spend the server's 60 for everyone. A pairing
window that a person opens on the server, outside which it takes no requests, is the planned answer;
it is not in this version.

**Limits a client applies:** a `requestId` and `pollToken` of 1 to 128 printable ASCII characters,
or the answer is one the client cannot use. It polls until the earlier of `expiresAt` and five
minutes after it opened, by its own clock, plus 30 seconds for a clock that differs, and then takes
the request as expired. A 429 on opening or revealing means the server takes no more requests for
now.

A client paired with several servers holds one client ID and secret for each.

## Tokens

- OAuth 2.0 client credentials at `POST /skakel/v2/token`, HTTPS only, as a form
  (`application/x-www-form-urlencoded`) with `grant_type=client_credentials`, `client_id` and
  `client_secret`. A server also takes the id and secret as HTTP Basic credentials (each part
  form-encoded as RFC 6749 says, so a literal `&` in either is written `%26`; a part with more than
  one field is refused), and answers `{ "access_token", "token_type": "Bearer", "expires_in" }`. Any other grant is `unsupported_grant_type`
  (400), a body that is not a form is `invalid_request` (400).
- Access tokens last 30 minutes. A token is an opaque string and a client never reads what is in
  it, so what it is, is the server's own business. Skakel's server issues 256 random bits as hex
  and remembers in memory who each one is for, so it has no signing key, and a server that
  restarts forgets its tokens: the next call is refused with `TOKEN_REFUSED` and the client gets a
  new one, as it does for any refused token. (The .NET server of Skakel 0.1 signed JWTs with RSA,
  and 0.2.1's Rust server with ECDSA; a client could not tell.)
- A client takes a token to last what `expires_in` says, held to between 2 and 30 minutes.
- A token works at every address and name of the server, because the server looks it up and does
  not check where it was asked for. The server publishes no OpenID Connect discovery document and
  no key set; the token endpoint is all there is.
- Each registered client has a **generation**, which the server records with each token it issues.
  Rotating a client's secret raises its generation, and revoking a client removes it. Every token
  and call from an older generation, or from a removed client, is refused, and every call still
  running is ended at once (see "Errors on gRPC calls").
- `ControlService.Hello` with a token answers `server` and `client_id`. An app's Test button uses
  it to check credentials, and with them that gRPC works.

**Limits a server applies:** 60 token requests per minute per address (see "Pairing" for what an
address is); one over the limit gets 429. After 10 wrong secrets for one registered client from one
address within a minute, requests for that client from that address get 429 until the minute is up,
the right secret included. Another address is not affected, so a wrong secret sent by someone who
only knows a client id cannot lock that client out where it really is; secrets are 256 random bits,
so guessing one is out of reach, and the limit only keeps a client with a stale secret from hammering
the endpoint. A body over 4 KiB gets 413, or 400 when the server only finds out while reading it, and so does a body that has not arrived in full within 10 seconds.
The per-address limit and the cap on the body apply before the server reads the request. A failed
request gets the OAuth error (`invalid_client`, 401), never the reason the secret was wrong.

A token from a revoked client, or from an older generation, fails authentication everywhere it is
presented, as an expired one does: `UNAUTHENTICATED` with the reason `TOKEN_REFUSED` on every gRPC
call, Skakel's and the app's, and 401 on an app's own HTTPS endpoints.

## Certificates

A server's certificate lasts ten years. Replacing it is a handover, so pinned clients are not cut
off:

1. The server prepares the next certificate and goes on presenting the current one.
2. On the control channel it sends `certificates { fingerprint, next_fingerprint }`. The client
   stores the next fingerprint as a second trusted one and sends
   `next_certificate_received { fingerprint }`, so the server can show who has it.
3. The server switches, and says so with another `certificates`. Clients make the next
   fingerprint their pinned one and drop the old.

Cancelling sends `certificates` with an empty next fingerprint, and clients forget it. A client that
was offline for the whole handover sees a certificate it does not know and must pair again.

A client acts on `certificates` only when its `fingerprint` is the certificate the control
connection presented, or the one a new connection to the server presents, as right after a switch,
when the control connection still runs on the old certificate. Anything else it ignores.

A server presents its current certificate on every new connection, so a connection made after the
switch never shows the old one. The Rust server turns TLS session resumption off for this: a resumed
session shows the client no certificate, and a client that proves a certificate by what a new
connection presents (see above) would take that for a failed proof.

## Following a server

When a client cannot reach a server's saved address at all (refused, timed out, no route, a name that
no longer resolves) and discovery hears a server with the pinned fingerprint, or the next one it was
told about, at another address or port, the client checks that address with `GET /skakel/info`
pinned to those fingerprints, within 5 seconds, and moves only if that answers. A certificate that
does not match, or credentials the server refused, are not a reason to move. An address it moved to
is not moved to again for five minutes.

Every address heard with such a fingerprint is a candidate, not only the one the list shows. One
search checks at most 8, the saved host first; an address that failed its check in the last five
minutes goes after those that did not. The search runs beside everything else, and a new list while
it runs makes it look once more when it is done.

## One port for HTTPS and gRPC

Everything on TCP runs over one TLS listener on the app's port, with the pinned certificate.

- **ALPN picks HTTP/2.** The server offers `h2` and `http/1.1` and picks `h2` when the client offers
  it. gRPC runs only over HTTP/2: a client makes gRPC calls only on a connection where ALPN chose
  `h2`, and a server that picks anything else for a client that offered `h2` did not answer like a
  Skakel server. The plain HTTPS calls (info, pairing, tokens, an app's own endpoints) work over
  either version. There is no gRPC over cleartext HTTP/2.
- **The content type tells a gRPC call.** A request whose content type is `application/grpc`, or
  starts with `application/grpc+`, goes to the server's gRPC services; every other request goes to
  its HTTPS routes. The paths never meet either: a gRPC path is `/<package>.<Service>/<Method>`,
  such as `/skakel.v2.StreamService/Open`, and Skakel's HTTPS paths start with `/skakel/`.
- **No compression.** Messages go uncompressed (`grpc-encoding` is `identity` or left out). A
  server need accept no other encoding; the Rust server refuses a call in any other with
  `UNIMPLEMENTED`. USB and serial data rarely compress, and a small server would spend more on
  compressing than the network saves.
- **Message limits.** A message on the control service is at most 1 MiB, and a frame on the stream
  service at most 16 MiB, both counted as encoded. A larger one ends the call with
  `RESOURCE_EXHAUSTED`, as gRPC does. An app's own services set their own limits, and on those the
  Rust server leaves tonic's answer as it is: a message over the limit ends the call with
  `OUT_OF_RANGE`. tonic gives the code `OUT_OF_RANGE` to a message over the limit, and a service
  may answer the same code for reasons of its own, such as a page past the end of a list. Only the
  words of tonic's message tell the two apart, so remapping an app's statuses would mean matching
  on text tonic does not promise to keep, and could rewrite a status the app meant. Skakel's own
  services never answer `OUT_OF_RANGE`, so for them the server checks the limit itself or remaps
  the code.
- **Keep-alive.** On every connection that carries gRPC, each end sends an HTTP/2 PING once it has
  heard nothing from the other for 15 seconds, and an end that has heard nothing from the other for
  30 seconds, no PING answer and no other frame, takes the connection for dead and closes it. A
  server takes pings at this rate from a client, with calls running or not. (Some gRPC servers answer pings more often than every five
  minutes with a `GOAWAY` of `ENHANCE_YOUR_CALM` unless told otherwise.)
- **The token is call metadata.** Every gRPC call carries `authorization: Bearer <token>`. The
  token is checked when a call starts. A connection is not signed in; its calls are.

## Errors on gRPC calls

A call that Skakel refuses or ends carries a gRPC status code and, in `grpc-status-details-bin`, a
`google.rpc.Status` with the same code and message and one `google.rpc.ErrorInfo` detail. Its
`domain` is `skakel` and its `reason` is one of the words below. The status message is for a
person, as the problem JSON's `detail` was in version 1; a client acts on the reason, never on the
message.

| Reason | Code | When | What a client does |
|---|---|---|---|
| `TOKEN_REFUSED` | `UNAUTHENTICATED` | A call starts with no token, an expired one, one the server did not sign, or one from an older generation or a removed client | Gets a new token and tries once more. When the token endpoint refuses the credentials, they are gone and the client has to pair again |
| `TOKEN_EXPIRED` | `UNAUTHENTICATED` | The control call reached the end of the token it was opened with | Opens the next control call with a fresh token, which it should already have done |
| `REVOKED` | `UNAUTHENTICATED` | The client was revoked | Stops using the credentials and says it has to pair again |
| `ROTATED` | `UNAUTHENTICATED` | The client's secret was rotated | The same as `REVOKED` |
| `STOPPING` | `UNAVAILABLE` | The server is stopping, or no longer serves this stream type | Connects again later, with a pause that grows |
| `BAD_OPEN` | `INVALID_ARGUMENT` | A stream's first frame is not `open`, its type breaks the rule, or the server heard no `open` within 15 seconds | Nothing to retry; a bug in the client |
| `BAD_FRAME` | `INVALID_ARGUMENT` | A frame where the stream does not allow one: a second `open`, an empty frame, anything before `opened` | Nothing to retry; a bug in the client |
| `NO_SUCH_TYPE` | `NOT_FOUND` | The server has no such stream type | Says the server does not offer it |
| `NO_SUCH_TARGET` | `NOT_FOUND` | The server has no such target (a port, a device) | Says so; the target may come back later |
| `IN_USE` | `FAILED_PRECONDITION` | The target is in use. The message names who holds it, when the app allows that | Says so, with the message |
| `BAD_TARGET` | `INVALID_ARGUMENT` | The stream's `target` is not what the type expects | Nothing to retry; a bug in the client or the app |
| `TARGET_GONE` | `NOT_FOUND` | After `opened`: the target went away (unplugged, removed) | Says so; the stream is over |

A stream type may end a stream for reasons of its own, with `ABORTED` and an `ErrorInfo` whose
domain is `skakel.streams.<type>`, such as `skakel.streams.serial`, and whose reason the type
defines. A reason is upper case letters, digits and `_`, starts with a letter, and is at most 63
characters. Skakel's reasons are only ever in the domain `skakel`, so a client tells the two apart
without knowing the type.

A status with no Skakel `ErrorInfo` is gRPC's own: `UNAVAILABLE` or `CANCELLED` from a connection
that dropped or stopped answering pings is a lost connection, `UNIMPLEMENTED` is a call the server
does not serve, and `RESOURCE_EXHAUSTED` is a message over the limit (`OUT_OF_RANGE` on an app's
own service, see "One port for HTTPS and gRPC"). An app's own services use their own domain, never
`skakel`.

**A call the client has stopped reading.** When the server ends a running call with `REVOKED`,
`ROTATED` or `STOPPING`, the status goes out after the messages it already sent on that call. Those
wait for the client's flow-control window, and HTTP/2 sends nothing after them on the call until
they have gone, so a client that has stopped reading a call learns that it ended only when it reads
again: the messages first, the status last. The server does not wait for that. It sends nothing
more on the call, a stream's handler is told at once and nothing more of the stream is read, and a
revoked or rotated client can start no new call with its old credentials. What stays is the data
already on its way, until the client reads or the connection closes; when the server stops, its
connections close a few seconds later anyway. The server does not reset
the call or close the connection to tell the client sooner: both would lose the reason, so the
client would see a lost connection instead of `REVOKED`, and closing would end every other call on
the connection too. A client hears the reason at once on its control call, which it always reads.
In some HTTP/2 implementations, the Rust one (`h2`) among them, unread messages hold the
connection's window as well as the call's, which is one more reason streams run on connections of
their own and a client reads or drops each call it makes on the control connection.

## Control channel

The control channel is `skakel.v2.ControlService`, in `control.proto`, on one long-lived HTTP/2
connection per client and server. The app's own calls should share that connection (see "An app's
own calls"); data streams should not (see "Streams").

`Connect` is a call both ways that stays open while the client wants the server's state:

| Direction | Message | When |
|---|---|---|
| Server to client | `certificates { fingerprint, next_fingerprint }` | First, as soon as the call starts, and whenever either changes |
| Server to client | `closing { reason }` | Just before the server ends the client's calls: `REVOKED`, `ROTATED` or `STOPPING` |
| Client to server | `next_certificate_received { fingerprint }` | The client stored the next certificate |

An end ignores a message whose kind it does not know. After `closing` the server ends the call with
the status of the same reason (see "Errors on gRPC calls"), so a client that misses the message
still learns why. A closing reason the client does not know counts as `STOPPING`.

After `REVOKED` or `ROTATED`, a client stops connecting with those credentials, which no longer
work, and says it has to pair again. After `STOPPING` it connects again later, with a pause that
grows, as after any connection it lost.

### Connecting, renewing, reconnecting

1. The client reads `/skakel/info` and gets a token, both over plain HTTPS.
2. It opens a TLS connection pinned to the fingerprint, with ALPN `h2`, and calls `Connect` with the
   token. It gives the server its request timeout (30 seconds unless the app sets another) to send
   `certificates`, and otherwise drops the call and tries again later.
3. **Renewing:** the server ends `Connect` with `TOKEN_EXPIRED` when the token it was opened with
   expires. Thirty seconds before that, the client gets a new token, calls `Connect` again on the
   same connection, and cancels the old call once the new one has sent `certificates`. Only the
   call is renewed; the connection stays. The client's other calls take the newest token as they
   start, and calls already running are not affected.
4. **Reconnecting:** when the connection drops or stops answering pings, the client opens a new one
   and starts again from step 2, with a pause that grows. A client starts connections and
   `Connect` calls at most once a second, whatever the tokens say.

A server allows more than one `Connect` call from a client at once, so a renewal overlaps the call
it replaces.

`Hello` answers the server's name and the client's id for a token, as `GET /skakel/v1/hello` did.

## An app's own calls

An app adds gRPC services of its own to the server, beside Skakel's, on the same port and
connection. Skakel's control channel carries only Skakel's messages.

- An app's package must not be `skakel` or start with `skakel.`.
- Every call to an app's service carries the same bearer token. The server checks it, and the
  client's generation, before the app sees the call, and refuses with `TOKEN_REFUSED` as for
  Skakel's own calls. The app learns which client called.
- When a client is revoked or rotated, or the server stops, the server ends that client's running
  calls to the app's services too, with `REVOKED`, `ROTATED` or `STOPPING`. A token that expires
  does not end a call already running; only the control call is bound to its token's life.
- An app that pushes state to clients does it with a server-streaming call of its own, and a
  client calls it again after it reconnects.
- An app may also keep HTTPS endpoints of its own, under paths it picks outside `/skakel/`, which
  take the same bearer token, as in version 1.

The app's `.proto` files are its own, and its services are versioned by its own package names.

**Why services of their own, not an envelope in Skakel's channel.** The other way was a generic
app message (a name and bytes) inside `Connect`. It would keep one ordered channel for Skakel's
messages and the app's, spare an app writing a `.proto` file, and stay close to version 1's hub.
But it would also make Skakel define again what gRPC already does: matching an answer to its call,
errors, cancelling and deadlines, and it would leave every app, in every language, decoding bytes
by name by hand. Separate services give apps typed, generated clients and servers, each call its own
status, flow control and cancellation, and an app protocol that changes without touching Skakel's.
What is lost is order between Skakel's messages and the app's, and nothing needs it: a certificate
handover does not touch app state, and revoking, rotating and stopping end every call with a status
anyway. An app that pushes state has to subscribe again after a reconnect, which the client crate
can tell it to do.

## Streams

A stream is one call to `skakel.v2.StreamService.Open`, in `streams.proto`, that carries one thing:
a USB device, a serial port, or whatever an app defines as a stream type.

- **A connection each.** A client should open each stream on a connection of its own, pinned and
  with ALPN `h2`, that carries no other call while the stream runs. HTTP/2 sends every call on a
  connection over one TCP connection, so one lost packet holds up all of them, and a bulk copy on
  one device would take the connection's flow-control window from the others. A server accepts a
  stream on any connection; sharing one is allowed, not advised.
- **Opening:** the client's first frame is `open { stream_type, target }`. `stream_type` is from
  `a-z`, `0-9` and `-`. `target` says what the stream is for, as a message the type defines,
  encoded; it is empty for a type that needs nothing. The client sends nothing more until the
  server answers. The server checks everything first, then sends `opened`, or refuses by ending the
  call before it with `BAD_OPEN`, `TOKEN_REFUSED`, `NO_SUCH_TYPE`, `NO_SUCH_TARGET`, `IN_USE` or
  `BAD_TARGET` (see "Errors on gRPC calls"). A client gives the server its request timeout (30
  seconds unless the app sets another) to answer.
- **Frames:** after `opened`, `data` frames carry the stream's bytes and `control` frames carry its
  control messages, one each, encoded as the type defines (protobuf for the types in this file).
  Both kinds are messages of one call, which HTTP/2 delivers in order, so frames keep their order
  across both kinds, and a control message takes effect between the bytes sent before it and the
  bytes sent after it. A type that has no control messages uses data frames only.
- **Flow:** HTTP/2 flow control does what the WebSocket's back pressure did. An end that stops
  reading stops granting window, so a slow reader slows the sender and nothing is lost.
- **The token** is checked when the stream opens. Its expiry does not end the stream; revoking,
  rotating and stopping do.
- **Closing:** the client closes a stream by ending its side of the call. The server sends what it
  still has and ends the call with `OK`. A client may cancel the call instead, and loses what was
  on its way. The server ends a stream with a status the client acts on:

  | Status | Meaning | Version 1 close code |
  |---|---|---|
  | `OK` | Closed normally | 1000 |
  | `UNAUTHENTICATED`, `REVOKED` | The client was revoked | 4001 |
  | `UNAUTHENTICATED`, `ROTATED` | The client's secret was rotated | 4002 |
  | `UNAVAILABLE`, `STOPPING` | The server is stopping, or no longer serves this type | 4003 |
  | `NOT_FOUND`, `TARGET_GONE` | The target went away (unplugged, removed) | 4004 |
  | `ABORTED`, domain `skakel.streams.<type>` | Defined by the stream type | 4100 to 4999 |

  A status with no Skakel `ErrorInfo`, such as `UNAVAILABLE` from a dropped connection, means the
  connection was lost.

Stream types used by more than one app are defined here, so apps of any licence can speak them.
A type only one app uses is defined by that app, in its own `.proto` file, and goes over this same
service. An app may also define a streaming call in a service of its own, but then the opening,
refusals and closes above are its own business.

**Throughput.** A data frame costs at most 10 bytes on top of its data: gRPC's 5-byte prefix, and
the field's tag and length. Its bytes are copied once into the send buffer, and a reader can take
them without copying again (prost reads `bytes` fields as `Bytes` when told to). HTTP/2 starts each
call and connection with a 64 KiB flow-control window, which holds one stream to 64 KiB per round
trip; for USB bulk traffic an implementation should raise both windows to 1 MiB or more, or let
them grow with the link (adaptive windows), and turn Nagle's algorithm off (`TCP_NODELAY`).

**Why one generic stream service.** Apps' calls are services of their own, so stream types could
have been too, each a typed streaming call. They go through one Skakel service instead because a
stream is more than a call: the opening, the refusals, the close reasons, order between data and
control, and ending streams on revoke are the same for every type, and Skakel implements them once,
with a single stream API in the client and one registry of types in the server, as in version 1.
The type still gets typed messages: its target and control messages are protobuf messages of its
own, carried as bytes. The data, which is what has to be fast, is a plain `bytes` field either way.

## The serial stream type

Type `serial`: one serial port on the server, used by one client at a time. Its messages are in
`serial.proto`.

**Opening:** `open { stream_type: "serial", target }`, where `target` is a `SerialTarget { port }`
and `port` is the port's id from the app's own list of ports. A second client gets `IN_USE`.

**Data:** `data` frames, the bytes as they leave and arrive at the port, with no framing of their
own. The server writes to the port only as fast as the port takes the bytes, and stops reading the
stream while the port's buffer is full, so a slow port slows the client down instead of losing
bytes.

**Control, client to server:** `control` frames, each a `SerialClientMessage`:

| Message | Fields | What |
|---|---|---|
| `line_settings` | `baud` (1 or more), `data_bits` (5 to 8), `parity` (none, odd, even, mark, space), `stop_bits` (one, one and a half, two), `flow_control` (none, RTS/CTS, XON/XOFF) | Change the port's settings. Every field is required: a zero or an unspecified value is a change the server answers with `unsupported` |
| `modem_lines` | `dtr`, `rts` (booleans, either may be left out) | Set the output lines |
| `break_signal` | `on` (boolean) | Start or end a break |
| `purge` | `input`, `output` (booleans, false when left out) | Throw away what is buffered on the server |

**Control, server to client:** `control` frames, each a `SerialServerMessage`:

| Message | Fields | What |
|---|---|---|
| `opened` | `line_settings`, `modem_status` | The first control message after `opened`: the port as it is now |
| `line_settings` | The fields above | The settings now on the port, after a change was applied. A client treats a change as done only when this comes back |
| `modem_status` | `cts`, `dsr`, `dcd`, `ri` (booleans) | Whenever an input line changes |
| `error` | `code` (`unsupported`, `framing`, `parity`, `overrun`), `detail` | A change the port refused, or errors the port reported. A refused change leaves the settings as they were |

**Rules:**

- The server applies a change only after the bytes sent before it have left the port, so a program
  that changes baud between two messages works.
- **Flow control runs on the server, on the real port.** XON/XOFF and RTS/CTS have to react within a
  few characters, which a round trip over the network cannot. With RTS/CTS the server drives RTS
  itself, and `modem_lines` changes to `rts` are ignored. With XON/XOFF the port's driver handles
  XON and XOFF and they do not appear in the data.
- **Values a reader does not know.** An enum value outside the lists above, or 0, in a message is
  not a reason to drop the message: a reader keeps the number, and a server answers a change that
  carries one with `unsupported`. A newer end may add values.
- A port the server cannot set a value on (a baud rate it does not support, one and a half stop
  bits with 8 data bits) gets an `error` with `unsupported`.
- The server answers each `line_settings` change once, with `line_settings` or an `unsupported`
  `error`, in the order the changes came. A client waits 10 seconds for the answer. An answer that
  comes after its change stopped waiting is taken as that change's, not the next one's, unless it
  echoes exactly what the next one asked for.

**Ending:** `ABORTED`, domain `skakel.streams.serial`, reason `PORT_FAULT`: the port reported a
fault and was closed. It was close code 4100 in version 1.

## Changes from version 1

Version 1 is Skakel 0.1.0. A version 1 client cannot talk to a version 2 server, or the other way
round: both ends update together, and each tells a person so through the version check.

| Version 1 | Version 2 |
|---|---|
| `"versions": [1]` in discovery and info | `"versions": [2]`; the discovery packet and the info answer are otherwise the same |
| `/skakel/v1/pair`, `/skakel/v1/token` | `/skakel/v2/pair`, `/skakel/v2/token`, otherwise the same |
| `GET /skakel/v1/hello` | `ControlService.Hello` |
| A SignalR hub at a path the app picks, JSON over a WebSocket | `skakel.v2.ControlService.Connect`, gRPC over HTTP/2 |
| `SkakelCertificates`, `SkakelClosing`, `SkakelNextCertificateReceived` | `certificates`, `closing`, `next_certificate_received`, typed messages in `control.proto`; the closing reason is an enum |
| App messages on the hub, named anything not starting with `Skakel` | The app's own gRPC services beside Skakel's, in packages not starting with `skakel` |
| Token in the `Authorization` header or the `access_token` query parameter | Token in the `authorization` metadata of each call only |
| The hub connection reconnects 30 seconds before its token expires | The `Connect` call is renewed on the same connection 30 seconds before its token expires |
| SignalR pings and WebSocket pings, every 15 seconds, 30 to give up | HTTP/2 PINGs on every connection, the same times, both ends |
| A WebSocket at `/skakel/v1/streams/{type}?...` | `skakel.v2.StreamService.Open`, the type and its target in the first frame |
| Refusals as HTTP 400, 401, 404, 409, 422 with problem JSON | gRPC status codes with a `google.rpc.ErrorInfo` reason: `BAD_OPEN`, `TOKEN_REFUSED`, `NO_SUCH_TYPE` or `NO_SUCH_TARGET`, `IN_USE`, `BAD_TARGET` |
| Close codes 1000, 4001 to 4004, 4100 to 4999 | `OK`, `REVOKED`, `ROTATED`, `STOPPING`, `TARGET_GONE`, and `ABORTED` with the type's own domain and reason |
| Binary frames for data, JSON text frames for control | `data` and `control` frames of one call, in order; the types here use protobuf for control |
| Serial control messages as JSON with `op` | `SerialClientMessage` and `SerialServerMessage` in `serial.proto`; `break` is `break_signal`; close code 4100 is `PORT_FAULT` |
| Streams share nothing but the port | Each stream should run on a connection of its own |

## Not in version 2

- IPv6 discovery.
- Several apps behind one port.
- Resuming a stream after the connection drops: a client opens a new one.
- QUIC and HTTP/3. UDP is blocked on some networks, which would need a fallback to TCP anyway.
  Worth another look if links on Wi-Fi drop when an address changes, or once the gRPC library serves
  HTTP/3, which needs no change to the messages.
- gRPC-Web, and compression.
