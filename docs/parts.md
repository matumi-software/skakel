# Skakel parts

Skakel is split into small parts so an app takes only what it needs. Each part is one Rust crate,
and a part depends only on the parts it cannot work without. The wire format is in
[protocol.md](protocol.md); this file says how the code is cut.

## The parts

| Part | Crate | Depends on |
|---|---|---|
| Wire | `skakel-wire` | nothing |
| Proto | `skakel-proto` | wire |
| Serial | `skakel-serial` | proto |
| Client | `skakel-client` | wire, proto, serial |
| Server | `skakel-server` | wire, proto |
| Virtual camera | `skakel-vcam` and `skakel-vcam-source` | nothing |

The server takes tokio, hyper, axum (its HTTPS routes), tonic (the generated services and their
router, without tonic's transport), tonic-types (the `google.rpc.Status` details of a refusal),
rustls (with ring) and rcgen, with everything they pull in under MIT, Apache-2.0, BSD, ISC, Zlib,
Unlicense or Unicode-3.0 (`r-efi`, built only for UEFI targets, offers LGPL as one of three options
and is used under its MIT one; checked with `cargo metadata`). It serves in one of two ways:

- **On a port of its own** (`SkakelServerBuilder::start`). Its own accept loop serves HTTPS and gRPC
  on one TLS port, so the certificate stays pinned and handed over the way the protocol says.
- **On the app's listener** (`SkakelServerBuilder::start_mounted`), for an app that serves its own
  pages on the same port, as Koppel does. The server binds nothing. The app mounts
  `SkakelServer::service`, a tower service with Skakel's HTTPS endpoints and gRPC services (the
  app's included, behind the token check), on its own hyper or axum server, and puts the caller's
  address on every request as axum's `ConnectInfo<SocketAddr>`, which every per-address limit
  counts by; a request without it is refused. The app's TLS acceptor takes
  `SkakelServer::tls_config`, which asks the server for its current certificate on every handshake
  and keeps session resumption off, so the handover works as on Skakel's own port. The app's
  connections take Skakel's HTTP/2 keep-alive and adaptive windows from `connection_builder`.
  Skakel keeps the certificate in both ways, because it decides when a prepared one is presented.

The wire is the same either way.

The client takes tokio and rustls (with ring), hyper's HTTP/1.1 client over tokio-rustls for pinned
HTTPS (one connection per request, no pool, no redirect, no proxy), tonic's generated clients over
hyper's HTTP/2 client and tokio-rustls for pinned gRPC connections it opens itself, one TCP
connection each, and if-addrs to find the networks to broadcast on. Both use one connector, so the
pin is checked the same way on every connection. tonic's own channel is not used:
it dials again behind the caller's back and shares one connection, where the client needs to pin
every handshake, keep connections to once a second, and give each stream a connection of its own.
The other crates take only small crates for JSON, hashing and randomness.

The server and the client speak protocol version 2, gRPC for the control channel and the streams.
Its wire format is the `.proto` files in `src/proto/skakel/v2/`. `skakel-proto` generates the Rust
code for them at build time, with `protox` compiling them in Rust (so no `protoc` is needed),
`prost` writing the messages and `tonic` the services, and the server, the client and the serial
part take their messages and services from it. Version 1's SignalR hub and WebSocket streams are
gone; they are at the tag `v0.1.0` and in the history.

The generated code is a part of its own rather than a module of `skakel-wire` so that an app that
only finds servers, or speaks the pairing calls, does not build prost and tonic. `skakel-proto`
depends on `skakel-wire` (for the reasons a call ends with and the hello contract, which it converts
to and from its messages) and not the other way round. `skakel-proto` takes prost alone by default; its `client` and `server` features add tonic's
generated clients and servers, without tonic's own transport, which Skakel does not use: its
connections are pinned to a certificate fingerprint.

The virtual camera is two crates because Windows loads the media source as a DLL of its own:
`skakel-vcam` is the producer and the installer, `skakel-vcam-source` is the DLL. The names keep the
short `vcam`.

## What each part holds

- **Wire:** everything that is plain data on the wire and that both ends compute or check, with no
  generated code. At the crate root: the protocol version, the paths and header names, the token
  lifetime, the keep-alive times and message limits, the JSON contracts (info, hello, problem),
  certificate fingerprints (normalising and comparing them), and the reasons a gRPC call is refused
  or ended, with their status codes. In `skakel_wire::discovery`: the UDP packet (the probe, the
  answer, building and reading them, the limits a client applies to an answer, and the cleaning of
  the name and app version a server announces). In `skakel_wire::pairing`: what both ends compute
  and send (the nonce, the commitment, the eight-digit code, the JSON bodies of the pairing calls
  with their states, and the cleaning of a client's name, `clean_client_name`, which a server
  applies and an app may apply before it shows one).
- **Proto:** the Rust code generated from the `.proto` files in `src/proto` (protocol version 2's
  control and stream services and the serial stream type's messages), and the tests that pin their
  field numbers and wire bytes. Messages always; the tonic clients with the `client` feature and the
  tonic servers with `server`.
- **Serial:** the serial stream type's wire format, whose messages are in
  `src/proto/skakel/v2/serial.proto`. The stream type and its target, line settings, modem lines,
  errors, and the control messages in both directions, as Rust types that encode to and decode from
  the generated messages. Wire format only: the code that opens a real port stays in the app (see
  `CLAUDE.md`).
- **Client:** what an app uses to reach servers. The browser that sends probes and keeps the list of
  servers found, the pairing flow, pinned HTTPS and gRPC connections, the info call, version
  picking, tokens, the control link (the control channel and its renewal, certificate handover,
  following a server to a new address), the app's own gRPC calls over it, data streams, and the serial
  connection built on a stream. Storage is the app's.
- **Server:** a server an app starts, on a port of its own or mounted on the app's listener, and
  adds its own gRPC services, stream types and HTTPS routes to. The discovery answerer, pairing approval, OAuth tokens, revoking clients, the
  certificate and its handover, the control and stream services, the token check in front of every
  gRPC service with the ending of a client's calls on revoke, rotate and stop, and the per-address
  limits. Storage is the app's, through a
  store it supplies.
- **Virtual camera:** a Windows 11 virtual camera any app can feed. It is not network code and has
  nothing to do with the other parts; see [virtual-camera.md](virtual-camera.md).

## Choosing

| An app that | Takes |
|---|---|
| Only needs a virtual camera (Tweeling) | Virtual camera |
| Reaches servers and uses their streams (a client) | Client, which brings wire, proto and serial |
| Serves clients (a server) | Server, which brings wire and proto |
| Speaks the serial stream on the server side without the client's code | Server and Serial |
| Only finds servers, or computes the pairing code, with no gRPC | Wire |
| Only needs the wire format, for its own transport or another language | Wire, and Proto for the messages |

## Checked against the code

The first proposal was protocol, discovery, pairing, client, server, serial and virtual camera. The
code changes four things about it:

- **Protocol, discovery and pairing are one part, Wire.** They were three crates released in lockstep
  with one version number, so the split bought no independent versioning, and each was a few hundred
  lines of plain data and checks. Discovery needed Protocol (`SkakelApp`, fingerprints, the app id
  rule) and Pairing needed the same cleaning rules, so an app took two or three crates for one idea:
  what is on the wire apart from the generated messages. They are modules of one crate now, and an
  app that only finds servers still builds no prost or tonic.
- **Discovery and pairing are the wire pieces, not the network code.** The browser that sends probes
  and the pairing flow both run on the client's pinned HTTP, its options and its failure types, which
  the control link uses too. Split off, they would need those from a part that in turn needs them
  back (the info call applies discovery's cleaning). So the packet and the code are what a server and
  a client share, and the client-side code that uses them stays in Client. The server's discovery
  answerer and pairing approval likewise stay in Server.
- **Serial is the wire format only, and Client depends on it.** The server never touches serial,
  because opening a port is the app's job. The client's serial connection and `Link::open_serial`
  sit on top of a data stream and need the messages, so Client takes Serial. It is the one place a
  client takes a part it may not use: a few hundred lines on top of Proto, which Client takes
  anyway.
- **Pinning is Client's, not a part of its own.** Pins, the pinned connections and the failure types
  are used by every client-side call, and nothing outside Client needs them.

The proposal's tokens, hub (now the control channel) and streams are in Client, as it said.

## Versions

All crates share one version number from the workspace and release together. Up to 0.1.0 Skakel
was a set of .NET packages; from 0.2.0 it is Rust only. The .NET packages 0.1.0 stay on NuGet.org
but are no longer developed, and their source is at the tag `v0.1.0`.
