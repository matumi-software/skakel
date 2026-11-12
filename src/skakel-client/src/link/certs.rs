//! The certificate handover, as the link learns it on the control channel.

use super::*;

/// The server told the link which certificate it presents and which one it will switch to. The link
/// is pinned to a certificate it trusts, so it may vouch for the next one: it is trusted as well, or
/// becomes the pinned one once the server presents it. Once the app saved the pins, the server is
/// told the client has the next one. A fingerprint that is not one is ignored. So is a statement
/// about a certificate this connection did not present, unless a new connection to the server
/// presents it, as after a switch, when the control connection still runs on the old certificate.
pub(super) async fn learn_certificates(
    inner: &Arc<Inner>,
    connection: &Connection,
    requests: &mpsc::Sender<ConnectRequest>,
    address: &Url,
    certificates: Certificates,
) {
    // The fingerprints are 32 bytes each, and the next one may be empty. Anything else is not a
    // fingerprint.
    let current = fingerprints::from_bytes(&certificates.fingerprint);
    let next_text = if certificates.next_fingerprint.is_empty() {
        None
    } else {
        fingerprints::from_bytes(&certificates.next_fingerprint)
    };
    let (Some(fingerprint), true) = (
        current,
        certificates.next_fingerprint.is_empty() || next_text.is_some(),
    ) else {
        log::warn!("The server sent certificates that are not fingerprints; ignored");
        return;
    };
    let next = next_text.as_deref();

    let on_this_connection = connection
        .presented()
        .is_some_and(|p| fingerprints::are_equal(&fingerprint, p));
    if !on_this_connection && !presents(inner, address, &fingerprint).await {
        log::warn!(
            "The server spoke of its certificate {fingerprint}, which it does not present; ignored"
        );
        return;
    }

    let after = {
        let mut pins = lock(&inner.pins);
        let after = pins.with_server_certificates(&fingerprint, next);
        *pins = after.clone();
        after
    };
    // Compared with what the app saved, not with what the link held a moment ago: a handover the
    // app failed to save is offered to it again on the next connection, and is acknowledged only
    // once the app has it.
    let unsaved = *lock(&inner.saved_pins) != after;
    if unsaved {
        log::info!(
            "The server's certificates changed: pinned {}, next {}",
            after.fingerprint(),
            after.next_fingerprint().unwrap_or("none")
        );
        inner.pins_watch.send_replace(after.clone());
        let _ = inner.events.send(LinkEvent::PinsChanged(after.clone()));
        if !save_pins(inner, after.clone()).await {
            // Not saved: the server is not told, and says it again on the next connection.
            return;
        }
        *lock(&inner.saved_pins) = after.clone();
    }

    if let (Some(stored), Some(said)) = (after.next_fingerprint(), next)
        && fingerprints::are_equal(stored, said)
    {
        let received = ConnectRequest {
            message: Some(connect_request::Message::NextCertificateReceived(
                NextCertificateReceived {
                    fingerprint: fingerprints::to_bytes(stored)
                        .map(|bytes| prost::bytes::Bytes::copy_from_slice(&bytes))
                        .unwrap_or_default(),
                },
            )),
        };
        if requests.send(received).await.is_err() {
            log::info!(
                "Telling {} the next certificate was stored failed: the call is over",
                http::authority(address)
            );
        }
    }
}

/// Whether a new connection to `address`, pinned as the link is, presents the certificate
/// `fingerprint`. Within five seconds, as a move's proof.
pub(super) async fn presents(inner: &Inner, address: &Url, fingerprint: &str) -> bool {
    let presented = http::presented();
    let client = HttpClient::new(inner.pins_fn(), Some(presented.clone()));
    match get_info(&client, address).await {
        Ok(()) => http::last_presented(&presented)
            .is_some_and(|p| fingerprints::are_equal(&p, fingerprint)),
        Err(error) => {
            log::info!(
                "certificate check on {} failed: {error}",
                http::authority(address)
            );
            false
        }
    }
}

/// `GET /skakel/info` on `server` over `client`, within the proof time. Any answer after the
/// handshake the client pins is the proof; a handshake that fails or takes too long is not.
pub(super) async fn get_info(client: &HttpClient, server: &Url) -> std::result::Result<(), String> {
    let url = server.join(INFO_PATH).map_err(|e| e.to_string())?;
    client
        .get(url)
        .timeout(PROOF_TIMEOUT)
        .send()
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}
