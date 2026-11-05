# Skakel

Skakel is the transport between apps on a local network. It covers how a client finds a server,
pairs with it, signs in, follows its state and moves data to and from it. Apps put their own
features on top.

[Koppel](https://github.com/matumi-software/koppel), which shares USB devices and serial ports over
the network, is the first app built on it.

*Skakel* is Afrikaans for a link in a chain, and to connect.

## Status

Nothing to install yet. The protocol is written up as a draft in [docs/protocol.md](docs/protocol.md),
taken from what Koppel does today. The code moves over from Koppel next.

## What it will hold

| Package | What |
|---|---|
| `Skakel.Client` | Find servers, pair, get tokens, pin the server's certificate, follow the control hub, open data streams |
| `Skakel.Server` | Issue tokens, approve pairing, revoke clients, host the control hub and the data stream endpoints |

Both are .NET libraries, published to NuGet.

## How it talks

- **Finding a server:** a UDP probe on the local network. A server answers with its name, port,
  certificate fingerprint and version.
- **Pairing:** a six-digit code that a person compares on both machines, so no secret is ever
  typed or copied.
- **Signing in:** OAuth 2.0 client credentials. The client pins the server's certificate.
- **Control:** REST for commands, SignalR for state the server pushes.
- **Data:** a binary WebSocket for each stream.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 Matumi Software.

Contributions are accepted under the same licence. Skakel takes no GPL code, so apps of any licence
can use it.
