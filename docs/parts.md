# Skakel parts

Skakel is split into small parts so an app takes only what it needs. Each part is one Rust crate,
and a part depends only on the parts it cannot work without. The wire format is in
[protocol.md](protocol.md); this file says how the code is cut.

## The parts

| Part | Crate | Depends on |
|---|---|---|
| Protocol | `skakel-protocol` | nothing |
| Discovery | `skakel-discovery` | protocol |
| Pairing | `skakel-pairing` | nothing |
| Serial | `skakel-serial` | nothing |
| Client | `skakel-client` | protocol, discovery, pairing, serial |
| Server | `skakel-server` | protocol, discovery, pairing |
| Virtual camera | `skakel-vcam` and `skakel-vcam-source` | nothing |

The server takes tokio, axum, rustls (with ring) and rcgen, with everything they pull in under MIT,
Apache-2.0, BSD, ISC, Unlicense or Unicode-3.0 (`r-efi`, built only for UEFI targets, offers LGPL as
one of three options and is used under its MIT one; checked with `cargo metadata`). The hub's
SignalR subset is written here: the SignalR crates on crates.io are clients.

The client takes tokio, reqwest and rustls (with ring) for pinned HTTPS, tokio-tungstenite for
WebSocket framing and if-addrs to find the networks to broadcast on. It has no SignalR dependency:
no maintained Rust SignalR client lets the certificate check be pinned, so the hub's JSON protocol
is written in the crate (see hub.rs). The other crates take only small crates for JSON, hashing and
randomness.

The virtual camera is two crates because Windows loads the media source as a DLL of its own:
`skakel-vcam` is the producer and the installer, `skakel-vcam-source` is the DLL. The names keep the
short `vcam`.

## What each part holds

- **Protocol:** what every other part builds on. The protocol version, the paths and header names,
  the token lifetime and stream keep-alive times, the JSON contracts (info, hello, problem),
  certificate fingerprints (normalising and comparing them), the hub's method names and messages
  (certificate handover, closing), and the WebSocket close codes.
- **Discovery:** the UDP packet. The probe, the answer, building and reading them, the limits a
  client applies to an answer, and the cleaning of the name and app version a server announces.
- **Pairing:** what both ends compute and send. The nonce, the commitment, the six-digit code, and
  the JSON bodies of the pairing calls (open, reveal, poll) with their states.
- **Serial:** the serial stream type's wire format. The stream type and its port query, line
  settings, modem lines, errors, and the control messages in both directions. Wire format only: the
  code that opens a real port stays in the app (see `CLAUDE.md`).
- **Client:** what an app uses to reach servers. The browser that sends probes and keeps the list of
  servers found, the pairing flow, pinned HTTP, the info call, version picking, tokens, the control
  link (hub, certificate handover, following a server to a new address), data streams, and the serial
  connection built on a stream. Storage is the app's.
- **Server:** a server an app starts and adds its own hubs, stream types and routes to. The
  discovery answerer, pairing approval, OAuth tokens, revoking clients, the certificate and its
  handover, the hub, stream endpoints, and the per-address limits. Storage is the app's, through a
  store it supplies.
- **Virtual camera:** a Windows 11 virtual camera any app can feed. It is not network code and has
  nothing to do with the other parts; see [virtual-camera.md](virtual-camera.md).

## Choosing

| An app that | Takes |
|---|---|
| Only needs a virtual camera (Tweeling) | Virtual camera |
| Reaches servers and uses their streams (a client) | Client, which brings protocol, discovery, pairing and serial |
| Serves clients (a server) | Server, which brings protocol, discovery and pairing |
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
  client takes a part it may not use: a few hundred lines, no other dependencies.
- **Pinning is Client's, not a part of its own.** Pins, the pinned connections and the failure types
  are used by every client-side call, and nothing outside Client needs them.

The proposal's tokens, hub and streams are in Client, as it said.

## Versions

All crates share one version number from the workspace and release together. Up to 0.1.0 Skakel
was a set of .NET packages; from 0.2.0 it is Rust only. The .NET packages 0.1.0 stay on NuGet.org
but are no longer developed, and their source is at the tag `v0.1.0`.
