//! Keeping the control channel up: the connect, renew and reconnect loop.

use super::*;

/// Sets the status and tells subscribers when it changed.
pub(super) async fn set_status(inner: &Inner, status: LinkStatus) {
    let changed = inner.status.send_if_modified(|current| {
        if *current == status {
            false
        } else {
            *current = status.clone();
            true
        }
    });
    if changed {
        let _ = inner.events.send(LinkEvent::Status(status));
    }
}

/// Keeps the control channel up until stopped. Catches everything: a link fails visibly, never
/// silently.
pub(super) async fn run_loop(inner: Arc<Inner>, stop: CancellationToken) {
    let mut backoff = MIN_BACKOFF;
    while !stop.is_cancelled() {
        let address = lock(&inner.address).clone();
        let started = inner.clock.instant();
        match connect_once(&inner, &address, &stop).await {
            Ok(None) => return,
            Ok(Some(end)) => {
                if ends_for_good(end.kind()) {
                    log::warn!(
                        "{} ended this client: {}. The link stops",
                        http::authority(&address),
                        end.code()
                    );
                    set_status(&inner, LinkStatus::with(LinkState::Closed, end)).await;
                    return;
                }
                // It was up; whatever ended it, the next try comes soon.
                log::warn!(
                    "The link to {} was lost: {}",
                    http::authority(&address),
                    end.code()
                );
                set_status(&inner, LinkStatus::with(LinkState::Failed, end)).await;
                if since(inner.clock.instant(), started) >= STABLE_AFTER {
                    backoff = MIN_BACKOFF;
                }
            }
            Err(error) => {
                if stop.is_cancelled() {
                    return;
                }
                if ends_for_good(error.kind()) {
                    log::warn!(
                        "{} refused this client: {}: {error:?}. The link stops",
                        http::authority(&address),
                        error.failure().code()
                    );
                    set_status(
                        &inner,
                        LinkStatus::with(LinkState::Closed, error.failure().clone()),
                    )
                    .await;
                    return;
                }
                log::warn!(
                    "The link to {} failed: {}: {error:?}",
                    http::authority(&address),
                    error.failure().code()
                );
                set_status(
                    &inner,
                    LinkStatus::with(LinkState::Failed, error.failure().clone()),
                )
                .await;
                if is_unreachable(&error) && inner.browser.is_some() {
                    lock(&inner.following).stranded = true;
                    request_follow(&inner);
                }
            }
        }

        pause(&inner, jittered(backoff), &stop).await;
        if stop.is_cancelled() {
            return;
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// True for a failure that trying again cannot mend: the server revoked the client, rotated its
/// secret, or its token endpoint refused the credentials. The client has to pair again.
pub(super) fn ends_for_good(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::Revoked | FailureKind::Rotated | FailureKind::RejectedCredentials
    )
}

/// A pause of between half of `delay` and all of it, so links to one server that restarted do not
/// all come back in the same instant.
pub(super) fn jittered(delay: Duration) -> Duration {
    let mut byte = [0u8; 1];
    if getrandom::fill(&mut byte).is_err() {
        return delay;
    }
    delay.mul_f64(0.5 + f64::from(byte[0]) / 510.0)
}

/// Waits before the next try. A move ends the wait at once.
pub(super) async fn pause(inner: &Inner, delay: Duration, stop: &CancellationToken) {
    tokio::select! {
        () = inner.clock.sleep(delay) => {}
        () = inner.wake.notified() => {}
        () = stop.cancelled() => {}
    }
}

/// Waits until a second has passed since the last connection or `Connect` call started, then notes
/// this one. False when the link was stopped meanwhile.
pub(super) async fn pace(inner: &Inner, stop: &CancellationToken) -> bool {
    let last = *lock(&inner.last_start);
    if let Some(last) = last {
        let gone = since(inner.clock.instant(), last);
        if gone < MIN_BACKOFF {
            tokio::select! {
                () = inner.clock.sleep(MIN_BACKOFF - gone) => {}
                () = stop.cancelled() => return false,
            }
        }
    }
    *lock(&inner.last_start) = Some(inner.clock.instant());
    !stop.is_cancelled()
}

/// One control call: what the client sends on it, and what the server answers.
pub(super) struct ControlCall {
    requests: mpsc::Sender<ConnectRequest>,
    answers: Streaming<ConnectResponse>,
}

/// Calls `Connect` on `connection` with `token` and waits up to `timeout` for the server's
/// `certificates`. An error status (a refusal) comes back as `Err(Ok(status))`; anything else that
/// went wrong as `Err(Err(error))`.
pub(super) async fn open_call(
    connection: &Connection,
    token: &str,
    timeout: Duration,
) -> std::result::Result<(ControlCall, Certificates), std::result::Result<Status, Error>> {
    let (requests, rx) = mpsc::channel(CONTROL_QUEUE);
    let mut control = ControlServiceClient::new(connection.service())
        .max_decoding_message_size(CONTROL_MESSAGE_LIMIT)
        .max_encoding_message_size(CONTROL_MESSAGE_LIMIT);
    let opening = async {
        let mut answers = control
            .connect(with_token(ReceiverStream::new(rx), token))
            .await?
            .into_inner();
        loop {
            match answers.message().await? {
                Some(ConnectResponse {
                    message: Some(connect_response::Message::Certificates(certificates)),
                }) => return Ok(Some((answers, certificates))),
                // A kind this end does not know.
                Some(ConnectResponse { message: None }) => {}
                Some(_) | None => return Ok(None),
            }
        }
    };
    match tokio::time::timeout(timeout, opening).await {
        Err(elapsed) => Err(Err(Error::caused(FailureKind::UnexpectedAnswer, elapsed))),
        Ok(Err(status)) => Err(Ok(status)),
        Ok(Ok(None)) => Err(Err(bad_answer(
            "The control call did not start with the certificates.",
        ))),
        Ok(Ok(Some((answers, certificates)))) => {
            Ok((ControlCall { requests, answers }, certificates))
        }
    }
}

/// When to renew a control call opened with `token`: half a minute ahead of its end; a token with
/// less than a minute left is renewed halfway through what it has.
pub(super) fn renew_at(inner: &Inner, token: &Token) -> Instant {
    let left = since(token.expires_at, inner.clock.instant());
    token.expires_at - REFRESH_AHEAD.min(left / 2)
}

/// How a control connection ended.
pub(super) enum End {
    Stopped,
    Failure(Failure),
}

/// One control connection, from start to end. `None` when the link was stopped; otherwise why the
/// connection ended. An error when it could not connect.
pub(super) async fn connect_once(
    inner: &Arc<Inner>,
    address: &Url,
    stop: &CancellationToken,
) -> Result<Option<Failure>> {
    let timeout = inner.options.request_timeout;
    set_status(inner, LinkStatus::of(LinkState::Connecting)).await;
    let info = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        info = read_info_with(&inner.http, address, timeout) => info?,
    };
    require_version(&info.versions)?;
    let mut token = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        token = inner.tokens.get() => token?,
    };
    if !pace(inner, stop).await {
        return Ok(None);
    }
    let connection = tokio::select! {
        () = stop.cancelled() => return Ok(None),
        connection = Connection::open(address, inner.pins_fn(), timeout) => connection?,
    };

    // A refused token gets one more try with a fresh one.
    let mut tries = 0;
    let (mut call, certificates) = loop {
        tries += 1;
        let opened = tokio::select! {
            () = stop.cancelled() => return Ok(None),
            opened = open_call(&connection, &token.value, timeout) => opened,
        };
        match opened {
            Ok(opened) => break opened,
            Err(Ok(status)) if is_token_refused(&status) && tries == 1 => {
                inner.tokens.forget(&token.value).await;
                token = tokio::select! {
                    () = stop.cancelled() => return Ok(None),
                    token = inner.tokens.get() => token?,
                };
                if !pace(inner, stop).await {
                    return Ok(None);
                }
            }
            Err(Ok(status)) => {
                if is_token_refused(&status) {
                    inner.tokens.forget(&token.value).await;
                }
                return Err(call_failed(status));
            }
            Err(Err(error)) => return Err(error),
        }
    };

    learn_certificates(inner, &connection, &call.requests, address, certificates).await;
    inner.control.send_replace(Some(connection.clone()));
    lock(&inner.following).stranded = false;
    log::info!("Connected to {}", http::authority(address));
    set_status(inner, LinkStatus::of(LinkState::Connected)).await;

    let end = serve(inner, &connection, &mut call, &mut token, address, stop).await;

    // Whatever ended it, this connection is over: nobody's calls go through it any more.
    inner.control.send_if_modified(|current| {
        if current.is_some() {
            *current = None;
            true
        } else {
            false
        }
    });
    Ok(match end {
        End::Stopped => None,
        End::Failure(failure) => Some(failure),
    })
}

/// What a closing reason or an ending status means for the link.
pub(super) fn failure_of(reason: Reason) -> Option<Failure> {
    match reason {
        Reason::Revoked => Some(Failure::of(FailureKind::Revoked)),
        Reason::Rotated => Some(Failure::of(FailureKind::Rotated)),
        Reason::Stopping => Some(Failure::of(FailureKind::ServerStopping)),
        _ => None,
    }
}

/// Runs a control connection: reads what the server says, renews the call before its token runs
/// out, and says why it ended.
pub(super) async fn serve(
    inner: &Arc<Inner>,
    connection: &Connection,
    call: &mut ControlCall,
    token: &mut Token,
    address: &Url,
    stop: &CancellationToken,
) -> End {
    let timeout = inner.options.request_timeout;
    let mut closing: Option<Reason> = None;
    loop {
        let wait = since(renew_at(inner, token), inner.clock.instant()).min(ACCESS_TOKEN_LIFETIME);
        let renew = tokio::select! {
            () = stop.cancelled() => return End::Stopped,
            () = connection.closed() => {
                return End::Failure(closing.and_then(failure_of).unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)));
            }
            () = inner.clock.sleep(wait) => true,
            answer = call.answers.message() => match answer {
                Ok(Some(ConnectResponse { message: Some(connect_response::Message::Certificates(certificates)) })) => {
                    learn_certificates(inner, connection, &call.requests, address, certificates).await;
                    false
                }
                Ok(Some(ConnectResponse { message: Some(connect_response::Message::Closing(said)) })) => {
                    // A reason this end does not know counts as stopping.
                    let reason = skakel_proto::closing_reason(said.reason);
                    log::info!("{} is closing the control call: {reason}", http::authority(address));
                    closing = Some(reason);
                    false
                }
                // A kind this end does not know.
                Ok(Some(_)) => false,
                Ok(None) => {
                    log::info!("{} ended the control call without a reason", http::authority(address));
                    return End::Failure(Failure::of(FailureKind::ConnectionLost));
                }
                Err(status) => match reason_of(&status) {
                    // The renewal was late, or the server's clock is ahead: renew now, with a token
                    // that is not the one that ran out.
                    Some(Reason::TokenExpired) => {
                        inner.tokens.forget(&token.value).await;
                        true
                    }
                    Some(reason) if failure_of(reason).is_some() => {
                        return End::Failure(failure_of(reason).expect("checked"));
                    }
                    Some(Reason::TokenRefused) => {
                        inner.tokens.forget(&token.value).await;
                        return End::Failure(Failure::of(FailureKind::ClientUnknown));
                    }
                    _ => {
                        log::info!(
                            "The control call to {} ended: {:?} {}",
                            http::authority(address),
                            status.code(),
                            status.message()
                        );
                        return End::Failure(
                            closing
                                .and_then(failure_of)
                                .unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)),
                        );
                    }
                },
            },
        };
        if !renew {
            continue;
        }

        // Renewing: a fresh token, a new call on the same connection, and the old one let go once
        // the new one has said the certificates. A refused token gets one more try with another.
        let mut tries = 0;
        let (renewed, certificates, fresh) = loop {
            tries += 1;
            let fresh = tokio::select! {
                () = stop.cancelled() => return End::Stopped,
                fresh = inner.tokens.get() => fresh,
            };
            let fresh = match fresh {
                Ok(fresh) => fresh,
                Err(error) => return End::Failure(error.failure().clone()),
            };
            if !pace(inner, stop).await {
                return End::Stopped;
            }
            let opened = tokio::select! {
                () = stop.cancelled() => return End::Stopped,
                opened = open_call(connection, &fresh.value, timeout) => opened,
            };
            match opened {
                Ok((renewed, certificates)) => break (renewed, certificates, fresh),
                Err(Ok(status)) if is_token_refused(&status) => {
                    inner.tokens.forget(&fresh.value).await;
                    if tries > 1 {
                        return End::Failure(Failure::of(FailureKind::ClientUnknown));
                    }
                }
                Err(Ok(status)) => {
                    return End::Failure(
                        reason_of(&status)
                            .and_then(failure_of)
                            .unwrap_or_else(|| Failure::of(FailureKind::ConnectionLost)),
                    );
                }
                Err(Err(error)) => {
                    log::info!(
                        "Renewing the control call to {} failed: {error:?}",
                        http::authority(address)
                    );
                    return End::Failure(Failure::of(FailureKind::ConnectionLost));
                }
            }
        };
        *call = renewed;
        *token = fresh;
        log::debug!("Renewed the control call to {}", http::authority(address));
        learn_certificates(inner, connection, &call.requests, address, certificates).await;
    }
}
