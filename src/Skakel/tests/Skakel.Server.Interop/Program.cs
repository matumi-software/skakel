using System.Globalization;
using System.Text.Json;
using Skakel.Server.Interop;
using Skakel.Server;

// A real Skakel server for the Rust crate skakel-client to talk to, on loopback. It reads one command
// per line on stdin and answers each with one line on stdout, "OK <json>" or "ERR <message>", and
// exits when stdin closes. A Rust test starts it, drives it, and lets go of its stdin.
//
//   start <store> [tcp] [udp]     starts a server on a free TCP port unless one is given (0 is none), answering
//                                 discovery on that UDP port when one is given. Servers started with the
//                                 same store name share a certificate and clients, as one server
//                                 restarted. {"id","port","fingerprint"}
//   stop <id>                     stops it
//   register <id> <name>          registers a client. {"clientId","clientSecret"}
//   requests <id>                 the pairing requests waiting. [{"id","clientName"}]
//   approve <id> <request> <code> types the code a person would. The approval's name
//   deny <id> <request>           refuses a pairing request. true or false
//   revoke <id> <client>          revokes a client. true or false
//   rotate <id> <client>          gives a client a new secret, and returns it
//   end-all <id>                  ends every connection as a stopping server does
//   prepare <id>                  prepares the next certificate and returns its fingerprint
//   switch <id>                   switches to it. {"from","to","notReceived"}
//   cancel <id>                   cancels the prepared one
//   clients <id>                  [{"id","name","hasNextCertificate"}]
//   versions <id> <1,2|off>       lists these versions in /skakel/info, as a server of another version
//   counts <id>                   {"tokens","negotiates"}
var stores = new Dictionary<string, InMemorySkakelStore>();
var benches = new Dictionary<int, Bench>();
var nextId = 0;
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);

// A test that died without closing stdin must not leave a server behind.
using var watchdog = new CancellationTokenSource(TimeSpan.FromMinutes(10));
watchdog.Token.Register(() => Environment.Exit(3));

string? line;
while ((line = Console.In.ReadLine()) is not null)
{
    string answer;
    try
    {
        answer = "OK " + JsonSerializer.Serialize(await RunAsync(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)), json);
    }
    catch (Exception ex) when (ex is InvalidOperationException or FormatException or IndexOutOfRangeException or KeyNotFoundException)
    {
        answer = "ERR " + ex.Message.ReplaceLineEndings(" ");
    }

    Console.Out.WriteLine(answer);
    Console.Out.Flush();
}

foreach (var bench in benches.Values)
{
    await bench.DisposeAsync();
}

return 0;

async Task<object?> RunAsync(string[] words)
{
    Bench Find() => benches.TryGetValue(Number(words[1]), out var found) ? found : throw new InvalidOperationException("No such server.");
    return words[0] switch
    {
        "start" => await StartAsync(words),
        "stop" => await StopAsync(Number(words[1])),
        "register" => await RegisterAsync(Find(), words[2]),
        "requests" => Find().Pairing.Overview.Requests.Select(r => new { r.Id, r.ClientName }),
        "approve" => (await Find().Pairing.ApproveAsync(words[2], words[3])).ToString(),
        "deny" => await Find().Pairing.DenyAsync(words[2]),
        "revoke" => await Find().Clients.RevokeAsync(words[2]),
        "rotate" => await Find().Clients.RotateSecretAsync(words[2]),
        "end-all" => await EndAllAsync(Find()),
        "prepare" => await Find().Keys.PrepareNextCertificateAsync(),
        "switch" => await SwitchAsync(Find()),
        "cancel" => await Find().Keys.CancelNextCertificateAsync(),
        "clients" => Find().Clients.All.Select(c => new { c.Id, c.Name, c.HasNextCertificate }),
        "versions" => SetVersions(Find(), words[2]),
        "counts" => new { Find().Tokens, Find().Negotiates },
        _ => throw new InvalidOperationException($"No command {words[0]}."),
    };
}

async Task<object> StartAsync(string[] words)
{
    if (!stores.TryGetValue(words[1], out var store))
    {
        stores[words[1]] = store = new InMemorySkakelStore();
    }

    int? tcp = words.Length > 2 && Number(words[2]) != 0 ? Number(words[2]) : null;
    int? udp = words.Length > 3 ? Number(words[3]) : null;
    var bench = await Bench.StartAsync(store, tcp, udp);
    var id = ++nextId;
    benches[id] = bench;
    return new { Id = id, bench.Port, bench.Keys.Fingerprint };
}

async Task<object> StopAsync(int id)
{
    if (benches.Remove(id, out var bench))
    {
        await bench.DisposeAsync();
    }

    return true;
}

static async Task<object> RegisterAsync(Bench bench, string name)
{
    var client = await bench.Clients.RegisterAsync(name);
    return new { client.ClientId, client.ClientSecret };
}

static async Task<object> EndAllAsync(Bench bench)
{
    await bench.Sessions.EndAllAsync();
    return true;
}

static async Task<object?> SwitchAsync(Bench bench)
{
    var switched = await bench.Keys.SwitchCertificateAsync();
    return switched is null ? null : new { switched.From, switched.To, switched.NotReceived };
}

static object SetVersions(Bench bench, string versions)
{
    bench.InfoVersions = versions == "off" ? null : [.. versions.Split(',').Select(Number)];
    return true;
}

static int Number(string text) => int.Parse(text, CultureInfo.InvariantCulture);
