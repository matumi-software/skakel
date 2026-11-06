using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Skakel.Protocol;

// Two commands, both on 127.0.0.1 and both over in a few seconds:
//
//   serve          binds a UDP socket on a free port, prints "PORT <number>", answers the first probe
//                  with the .NET discovery answer and exits.
//   probe <port>   sends the .NET probe to that port, waits up to three seconds for an answer, prints
//                  what SkakelDiscovery.TryParseAnswer read as JSON and exits 0, or exits 1 when none came.
var command = args.Length > 0 ? args[0] : "";
return command switch
{
    "serve" => await ServeAsync(),
    "probe" when args.Length == 2 && int.TryParse(args[1], out var port) => await ProbeAsync(port),
    _ => Usage(),
};

static async Task<int> ServeAsync()
{
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    Console.WriteLine($"PORT {((IPEndPoint)socket.LocalEndPoint!).Port}");
    Console.Out.Flush();

    var answer = SkakelDiscovery.CreateAnswer(new DiscoveryAnswer("dotnet-helper", 5240, string.Join(':', Enumerable.Repeat("EF", 32)), new SkakelApp("koppel", "0.1.1"), [1]));
    var buffer = new byte[2048];
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
    while (true)
    {
        var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
        if (SkakelDiscovery.IsProbe(buffer.AsSpan(0, received.ReceivedBytes)) && received.RemoteEndPoint is IPEndPoint from)
        {
            await socket.SendToAsync(answer, SocketFlags.None, from, timeout.Token);
            return 0;
        }
    }
}

static async Task<int> ProbeAsync(int port)
{
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    await socket.SendToAsync(SkakelDiscovery.CreateProbe(), SocketFlags.None, new IPEndPoint(IPAddress.Loopback, port));

    var buffer = new byte[2048];
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    try
    {
        while (true)
        {
            var received = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), timeout.Token);
            if (SkakelDiscovery.TryParseAnswer(buffer.AsSpan(0, received.ReceivedBytes), out var answer))
            {
                Console.WriteLine(JsonSerializer.Serialize(answer, SkakelJson.Options));
                return 0;
            }
        }
    }
    catch (OperationCanceledException)
    {
        return 1;
    }
}

static int Usage()
{
    Console.Error.WriteLine("Usage: Skakel.Discovery.Interop serve | probe <port>");
    return 2;
}
