//! Following a server that moved to another address on the local network.

use super::*;

/// Starts a search for the server in the background, while the link cannot reach it. A request
/// while one runs has it look once more when it is done, at the addresses heard by then, so
/// searches never pile up and a slow proof never holds up the browser's other listeners.
pub(super) fn request_follow(inner: &Arc<Inner>) {
    if lock(&inner.run).is_none() {
        return;
    }
    let Some(browser) = inner.browser.clone() else {
        return;
    };
    let mut following = lock(&inner.following);
    if !following.stranded {
        return;
    }
    if following.running {
        following.again = true;
        return;
    }
    following.running = true;
    let inner = inner.clone();
    following.task = Some(tokio::spawn(async move {
        follow_while_asked(inner, browser).await
    }));
}

pub(super) async fn follow_while_asked(inner: Arc<Inner>, browser: Browser) {
    loop {
        follow(&inner, &browser.entries()).await;
        let mut following = lock(&inner.following);
        let stopped = lock(&inner.run).is_none();
        if !following.again || !following.stranded || stopped {
            following.again = false;
            following.running = false;
            return;
        }
        following.again = false;
    }
}

/// Moves the link to where its server is now, if discovery heard it elsewhere and it proved it
/// holds the certificate.
pub(super) async fn follow(inner: &Arc<Inner>, servers: &[crate::browser::DiscoveredServer]) {
    let from = lock(&inner.address).clone();
    let pins = lock(&inner.pins).clone();
    let to = inner
        .moves
        .find(&from, &pins, servers, |url| proves(inner, url))
        .await;
    let Some(to) = to else {
        return;
    };
    {
        let mut address = lock(&inner.address);
        if *address != from {
            return;
        }
        *address = to.clone();
        lock(&inner.following).stranded = false;
    }
    inner.wake.notify_one();
    log::info!(
        "The server stopped answering at {} and was found at {}; the link follows it",
        http::authority(&from),
        http::authority(&to)
    );
    inner.address_watch.send_replace(to.clone());
    let _ = inner.events.send(LinkEvent::AddressChanged(to));
}

/// Whether `url` holds a certificate the link trusts: `GET /skakel/info` over the pinned client,
/// with no token, within five seconds. Any answer after the pinned handshake proves it; a handshake
/// that fails or takes too long does not.
pub(super) fn proves(inner: &Arc<Inner>, url: Url) -> impl Future<Output = bool> + use<> {
    let http = inner.http.clone();
    async move {
        match get_info(&http, &url).await {
            Ok(()) => true,
            Err(error) => {
                log::warn!(
                    "A server with the pinned fingerprint was heard at {}, but it did not prove it holds the certificate: {error}",
                    http::authority(&url)
                );
                false
            }
        }
    }
}
