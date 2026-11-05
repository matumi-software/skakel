# Skakel

Skakel is the transport between apps on a local network. It covers how a client finds a server,
pairs with it, signs in, follows its state and moves data to and from it. Apps put their own
features on top.

[Koppel](https://github.com/matumi-software/koppel), which shares USB devices and serial ports over
the network, is the first app built on it.

*Skakel* is Afrikaans for a link in a chain, and to connect.

## Status

Version 0.1.0. Protocol version 1 is settled in [docs/protocol.md](https://github.com/matumi-software/skakel/blob/main/docs/protocol.md), and the
client and server libraries are tested against each other. Koppel 0.1.1 is the first app built on them.

## What it holds

| Package | What |
|---|---|
| `Skakel.Protocol` | What clients and servers share: wire constants, discovery packets, the pairing code, the JSON contract and the serial stream's messages |
| `Skakel.Client` | Find servers, pair, get tokens, pin the server's certificate, follow the control hub, open data streams |
| `Skakel.Server` | Issue tokens, approve pairing, revoke clients, host the control hub and the data stream endpoints |

All three are .NET 10 libraries on NuGet.org:

```sh
dotnet add package Skakel.Client
```

## How it talks

- **Finding a server:** a UDP probe on the local network. A server answers with its name, port,
  certificate fingerprint and version.
- **Pairing:** a six-digit code that a person compares on both machines, so no secret is ever
  typed or copied.
- **Signing in:** OAuth 2.0 client credentials. The client pins the server's certificate.
- **Control:** REST for commands, SignalR for state the server pushes.
- **Data:** a binary WebSocket for each stream.

## License

MIT, see [LICENSE](https://github.com/matumi-software/skakel/blob/main/LICENSE). Copyright (c) 2026 Matumi Software.

Contributions are accepted under the same licence. Skakel takes no GPL code, so apps of any licence
can use it.
