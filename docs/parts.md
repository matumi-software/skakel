# Skakel parts

Skakel is split into small parts so an app takes only what it needs. Each part is one Rust crate,
and a part depends only on the parts it cannot work without. The wire format is in
[protocol.md](protocol.md); this file says how the code is cut.

## The parts

| Part | Crate | Depends on |
|---|---|---|
| Protocol | `skakel-protocol` | nothing |
| Proto | `skakel-proto` | nothing |
| Discovery | `skakel-discovery` | protocol |
| Pairing | `skakel-pairing` | nothing |
| Serial | `skakel-serial` | proto |
| Client | `skakel-client` | protocol, proto, discovery, pairing, serial |
| Server | `skakel-server` | protocol, proto, discovery, pairing |
| Virtual camera | `skakel-vcam` and `skakel-vcam-source` | nothing |

The server takes tokio, hyper, axum (its HTTPS routes), tonic (the generated services and their
router, without tonic's transport), tonic-types (the `google.rpc.Status` details of a refusal),
rustls (with ring) and rcgen, with everything they pull in under MIT, Apache-2.0, BSD, ISC, Zlib,
Unlicense or Unicode-3.0 (`r-efi`, built only for UEFI targets, offers LGPL as one of three options
and is used under its MIT one; checked with `cargo metadata`). Its own accept loop serves HTTPS and
gRPC on one TLS port, so the certificate stays pinned and handed over the way the protocol says.

The client takes tokio, reqwest and rustls (with ring) for pinned HTTPS, tonic's generated clients
over hyper's HTTP/2 client and tokio-rustls for pinned gRPC connections it opens itself, one TCP
connection each, and if-addrs to find the networks to broadcast on. tonic's own channel is not used:
it dials again behind the caller's back and shares one connection, where the client needs to pin
every handshake, keep connections to once a second, and give each stream a connection of its own.
The other crates take only small crates for JSON, hashing and randomness.

The server and the client speak protocol version 2, gRPC for the control channel and the streams.
Its wire format is the `.proto` files in `src/proto/skakel/v2/`. `skakel-proto` generates the Rust
code for them at build time, with `protox` compiling them in Rust (so no `protoc` is needed),
`prost` writing the messages and `tonic` the services, and the server, the client and the serial
part take their messages and services from it. Version 1's SignalR hub and WebSocket streams are
gone; they are at the tag `v0.1.0` and in the history.

The generated code is a part of its own rather than a module of `skakel-protocol` because
Discovery depends on Protocol, and an app that only finds servers should not build prost and tonic.
`skakel-proto` takes prost alone by default; its `client` and `server` features add tonic's
generated clients and servers, without tonic's own transport, which Skakel does not use: its
connections are pinned to a certificate fingerprint.

The virtual camera is two crates because Windows loads the media source as a DLL of its own:
`skakel-vcam` is the producer and the installer, `skakel-vcam-source` is the DLL. The names keep the
short `vcam`.

## What each part holds

- **Protocol:** what every other part builds on. The protocol version, the paths and header names,
  the token lifetime, the keep-alive times and message limits, the JSON contracts (info, hello,
  problem), certificate fingerprints (normalising and comparing them), and the reasons a gRPC call
  is refused or ended, with their status codes.
- **Proto:** the Rust code generated from the `.proto` files in `src/proto` (protocol version 2's
  control and stream services and the serial stream type's messages), and the tests that pin their
  field numbers and wire bytes. Messages always; the tonic clients with the `client` feature and the
  tonic servers with `server`.
- **Discovery:** the UDP packet. The probe, the answer, building and reading them, the limits a
  client applies to an answer, and the cleaning of the name and app version a server announces.
- **Pairing:** what both ends compute and send. The nonce, the commitment, the six-digit code, and
  the JSON bodies of the pairing calls (open, reveal, poll) with their states.
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
- **Server:** a server an app starts and adds its own gRPC services, stream types and HTTPS
  routes to. The discovery answerer, pairing approval, OAuth tokens, revoking clients, the
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
| Reaches servers and uses their streams (a client) | Client, which brings protocol, discovery, pairing and serial |
| Serves clients (a server) | Server, which brings protocol, proto, discovery and pairing |
| Speaks the serial stream on the server side without the client's code | Server and Serial |
| Only needs the wire format, for its own transport or another language | Protocol, and the parts whose packets it handles |

## Checked against the code

The first proposal was protocol, discovery, pairing, client, server, serial and virtual camera. The
code changes three things about it:

- **Discovery and pairing are the wire pieces, not the network code.** The browser that sends probes
  and the pairing flow both run on the client's pinned HTTP, its options and its failure types, which
  the control link uses too. Split off, they would need those from a part that in turn needs them
  back (the info call applies discovery's cleaning). So the packet and the code are the parts a
  server and a client share, and the client-side code that uses them stays in Client. The server's
  discovery answerer and pairing approval likewise stay in Server.
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
