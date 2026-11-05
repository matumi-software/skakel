using Microsoft.AspNetCore.SignalR.Client;

namespace Skakel.Client;

/// <summary>
/// The app's own hub handlers. A link makes a new hub connection each time it connects, so the handlers
/// are kept here and put on every new connection before it starts, and on the live one when added later.
/// </summary>
internal sealed class HubHandlers
{
    private readonly Lock _gate = new();
    private readonly List<Registration> _all = [];
    private HubConnection? _hub;

    public IDisposable Add(string methodName, Type[] parameterTypes, Func<object?[], Task> handler)
    {
        var registration = new Registration(this, methodName, parameterTypes, handler);
        lock (_gate)
        {
            _all.Add(registration);
            if (_hub is { } hub)
            {
                registration.Attach(hub);
            }
        }

        return registration;
    }

    /// <summary>Puts every handler on a new connection, which becomes the one later handlers go on.</summary>
    public void AttachAll(HubConnection hub)
    {
        lock (_gate)
        {
            _hub = hub;
            foreach (var registration in _all)
            {
                registration.Attach(hub);
            }
        }
    }

    /// <summary>The connection is gone; its subscriptions go with it.</summary>
    public void Detach(HubConnection hub)
    {
        lock (_gate)
        {
            if (ReferenceEquals(_hub, hub))
            {
                _hub = null;
            }
        }
    }

    private sealed class Registration(HubHandlers owner, string methodName, Type[] parameterTypes, Func<object?[], Task> handler) : IDisposable
    {
        private IDisposable? _subscription;
        private bool _disposed;

        /// <summary>With the owner's gate held.</summary>
        public void Attach(HubConnection hub)
        {
            if (!_disposed)
            {
                _subscription = hub.On(methodName, parameterTypes, (arguments, _) => handler(arguments), this);
            }
        }

        public void Dispose()
        {
            lock (owner._gate)
            {
                _disposed = true;
                owner._all.Remove(this);
                _subscription?.Dispose();
                _subscription = null;
            }
        }
    }
}
