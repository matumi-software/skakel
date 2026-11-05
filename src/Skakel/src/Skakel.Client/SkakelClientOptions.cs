using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Skakel.Client;

/// <summary>How the client's parts log, keep time and wait. The link settings apply to <see cref="SkakelLink"/> only.</summary>
public sealed class SkakelClientOptions
{
    /// <summary>Where the detail of every failure goes. Nothing is logged unless set.</summary>
    public ILoggerFactory? LoggerFactory { get; set; }

    /// <summary>The clock. The system's unless set.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>How long one HTTP request may take. A server on slow hardware can take many seconds over its first request after a start.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>For a link: the hub's path under <c>/skakel/v1/</c>, as the app's server mapped it. <c>hub</c> unless set.</summary>
    public string HubPath { get; set; } = "hub";

    /// <summary>
    /// For a link: the browser it listens to, so it can follow its server to another address on the local
    /// network when the saved one stops answering. Without one, a link stays where it is.
    /// </summary>
    public SkakelBrowser? Browser { get; set; }

    /// <summary>For a link: changes to the JSON options of the hub's messages, for the app's own message types.</summary>
    public Action<JsonSerializerOptions>? ConfigureHubJson { get; set; }

    internal ILoggerFactory Loggers => LoggerFactory ?? NullLoggerFactory.Instance;

    internal TimeProvider Time => TimeProvider ?? TimeProvider.System;
}
