//! A `serial` stream: one serial port on the server. Data goes both ways through
//! [`send`](SerialConnection::send) and [`recv`](SerialConnection::recv); the port's settings and
//! lines are changed with the control messages, and what the server says about the port comes back
//! as properties and events. A change to the line settings counts as done only when the server
//! echoes it.
//!
//! One task reads the stream, so control messages are seen while the app is not reading data. Data
//! waits in a small buffer: an app that stops reading stops the reads, and the server slows down the
//! port instead of losing bytes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prost::bytes::Bytes;
use skakel_serial::{ClientMessage, ErrorCode, LineSettings, ModemStatus, ServerMessage};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::failure::{Error, FailureKind, bad_answer};
use crate::streams::{Frame, StreamClose, StreamConnection};

/// How long the server has to say the port is open after the stream opened.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the server has to answer a change to the line settings, unless set otherwise.
const DEFAULT_CHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest control message read; a longer one is dropped.
const MAX_CONTROL_BYTES: usize = 64 * 1024;

/// How many chunks of data wait for the app to read them.
const DATA_CHUNKS: usize = 16;

/// What became of a change to the line settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialChange {
    /// True when the server echoed the settings: the change is done. False when the port refused it.
    pub applied: bool,
    /// The settings on the port now: the echoed ones, or the ones before a refused change.
    pub line_settings: LineSettings,
    /// Why the port refused, from the server, for a person.
    pub detail: Option<String>,
}

/// What the port reports besides the answer to a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerialEvent {
    /// An input line changed. [`SerialConnection::modem_status`] has the new state already.
    ModemStatus(ModemStatus),
    /// The port reported an error (framing, parity, overrun), or refused something that was not a
    /// line settings change.
    Error {
        /// What kind of error.
        code: ErrorCode,
        /// What happened, for a person.
        detail: Option<String>,
    },
}

enum Answer {
    Applied(LineSettings),
    Refused(Option<String>),
}

struct Pending {
    settings: LineSettings,
    answer: oneshot::Sender<Answer>,
}

#[derive(Default)]
struct Answers {
    change: Option<Pending>,
    /// Changes that stopped waiting after they were sent: the next answers that come in are theirs.
    owed: u32,
}

struct Shared {
    line_settings: Mutex<LineSettings>,
    modem_status: Mutex<ModemStatus>,
    answers: Mutex<Answers>,
    events: broadcast::Sender<SerialEvent>,
}

/// A `serial` stream.
pub struct SerialConnection {
    stream: Arc<StreamConnection>,
    shared: Arc<Shared>,
    data: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    changing: tokio::sync::Mutex<()>,
    change_timeout: Mutex<Duration>,
    receiving: JoinHandle<()>,
}

impl std::fmt::Debug for SerialConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SerialConnection").finish_non_exhaustive()
    }
}

impl Drop for SerialConnection {
    fn drop(&mut self) {
        self.receiving.abort();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl SerialConnection {
    /// Waits for the server's `opened`, then starts reading.
    pub(crate) async fn start(stream: StreamConnection) -> Result<Self, Error> {
        let opened = tokio::time::timeout(OPEN_TIMEOUT, async {
            match stream.recv().await {
                None => {
                    log::info!(
                        "A serial stream closed with {:?} before the port opened",
                        stream.close_info().map(|c| c.code)
                    );
                    Err(Error::of(FailureKind::ConnectionLost))
                }
                Some(Frame::Control(bytes)) if bytes.len() <= MAX_CONTROL_BYTES => {
                    match ServerMessage::decode(&bytes) {
                        Ok(ServerMessage::Opened {
                            line_settings,
                            modem_status,
                        }) => Ok((line_settings, modem_status)),
                        _ => Err(bad_answer(
                            "The serial stream did not start with an opened message.",
                        )),
                    }
                }
                Some(_) => Err(bad_answer(
                    "The serial stream did not start with an opened message.",
                )),
            }
        })
        .await
        .map_err(Error::from_cause)?;
        let (line_settings, modem_status) = opened?;

        let (events, _) = broadcast::channel(64);
        let shared = Arc::new(Shared {
            line_settings: Mutex::new(line_settings),
            modem_status: Mutex::new(modem_status),
            answers: Mutex::new(Answers::default()),
            events,
        });
        let stream = Arc::new(stream);
        let (data_tx, data_rx) = mpsc::channel(DATA_CHUNKS);
        let receiving = tokio::spawn(receive(stream.clone(), shared.clone(), data_tx));
        Ok(Self {
            stream,
            shared,
            data: tokio::sync::Mutex::new(data_rx),
            changing: tokio::sync::Mutex::new(()),
            change_timeout: Mutex::new(DEFAULT_CHANGE_TIMEOUT),
            receiving,
        })
    }

    /// The stream underneath.
    pub fn stream(&self) -> &StreamConnection {
        &self.stream
    }

    /// The port's settings, as the server last said.
    pub fn line_settings(&self) -> LineSettings {
        *lock(&self.shared.line_settings)
    }

    /// The port's input lines, as the server last said.
    pub fn modem_status(&self) -> ModemStatus {
        *lock(&self.shared.modem_status)
    }

    /// Modem line changes and errors the port reports, as they come.
    pub fn events(&self) -> broadcast::Receiver<SerialEvent> {
        self.shared.events.subscribe()
    }

    /// Completes when the stream ended, with how: a [`StreamCloseReason::TypeDefined`] close whose
    /// `type_reason` is [`PORT_FAULT`](skakel_serial::PORT_FAULT) is a port that reported a fault.
    ///
    /// [`StreamCloseReason::TypeDefined`]: crate::StreamCloseReason::TypeDefined
    pub async fn closed(&self) -> StreamClose {
        self.stream.closed().await
    }

    /// Sends bytes to the port.
    pub async fn send(&self, data: impl Into<Bytes>) -> Result<(), Error> {
        self.stream.send_data(data).await
    }

    /// The next bytes that came from the port, or `None` once the stream has ended and everything
    /// was read. One task at a time reads.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.data.lock().await.recv().await
    }

    /// How long the server has to answer a change to the line settings: 10 seconds unless set.
    pub fn set_change_timeout(&self, timeout: Duration) {
        *lock(&self.change_timeout) = timeout;
    }

    /// Changes the port's settings and waits until the server echoes them, or the port refuses. One
    /// change at a time; the server has 10 seconds to answer, so a change it never answers does not
    /// hold up the next. An answer that comes after its change stopped waiting is not taken for the
    /// next one.
    ///
    /// Every setting is sent; the protocol has no partial change. Fails with
    /// [`FailureKind::ConnectionLost`] when the stream ended before the server answered, or
    /// [`FailureKind::UnexpectedAnswer`] when the server did not answer in time. Either way the
    /// change may still be applied; [`line_settings`](Self::line_settings) follows what the server
    /// says. Dropping the future stops waiting.
    pub async fn set_line_settings(&self, settings: LineSettings) -> Result<SerialChange, Error> {
        let _changing = self.changing.lock().await;
        let (answer, answered) = oneshot::channel();
        let mut answered = answered;
        lock(&self.shared.answers).change = Some(Pending { settings, answer });
        let sent = AtomicBool::new(false);

        let result = async {
            if self.stream.close_info().is_some() {
                return Err(Error::of(FailureKind::ConnectionLost));
            }
            let timeout = *lock(&self.change_timeout);
            let waited = tokio::time::timeout(timeout, async {
                self.send_control(&ClientMessage::LineSettings(settings)).await?;
                sent.store(true, Ordering::SeqCst);
                match (&mut answered).await {
                    Ok(Answer::Applied(applied)) => Ok(SerialChange {
                        applied: true,
                        line_settings: applied,
                        detail: None,
                    }),
                    Ok(Answer::Refused(detail)) => Ok(SerialChange {
                        applied: false,
                        line_settings: self.line_settings(),
                        detail,
                    }),
                    Err(_) => Err(Error::of(FailureKind::ConnectionLost)),
                }
            })
            .await;
            match waited {
                Ok(result) => result,
                Err(elapsed) => {
                    log::warn!(
                        "The server did not answer a change to the line settings on a serial stream within {} seconds",
                        timeout.as_secs_f64()
                    );
                    Err(Error::caused(FailureKind::UnexpectedAnswer, elapsed))
                }
            }
        }
        .await;

        let mut answers = lock(&self.shared.answers);
        // Sent and not answered: its answer is still on its way. Looked at while the change still
        // holds the sending end, or the receiver would only say it is closed.
        let unanswered = sent.load(Ordering::SeqCst)
            && matches!(
                answered.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            );
        answers.change = None;
        if unanswered {
            answers.owed += 1;
        }
        result
    }

    /// Sets the output lines. A line left `None` stays as it is. RTS is ignored while flow control
    /// is RTS/CTS.
    pub async fn set_modem_lines(&self, dtr: Option<bool>, rts: Option<bool>) -> Result<(), Error> {
        self.send_control(&ClientMessage::ModemLines { dtr, rts })
            .await
    }

    /// Starts or ends a break.
    pub async fn set_break(&self, on: bool) -> Result<(), Error> {
        self.send_control(&ClientMessage::Break { on }).await
    }

    /// Throws away what is buffered on the server: the bytes read from the port and not sent yet
    /// (`input`), and the bytes waiting to be written to it (`output`).
    pub async fn purge(&self, input: bool, output: bool) -> Result<(), Error> {
        self.send_control(&ClientMessage::Purge { input, output })
            .await
    }

    /// Ends the client's side of the stream and waits briefly for the server to end it.
    pub async fn close(&self) {
        self.stream.close().await;
    }

    /// One frame at a time, so a control message lands between the bytes sent before and after it.
    async fn send_control(&self, message: &ClientMessage) -> Result<(), Error> {
        self.stream.send_control(message.encode()).await
    }
}

async fn receive(stream: Arc<StreamConnection>, shared: Arc<Shared>, data: mpsc::Sender<Vec<u8>>) {
    while let Some(frame) = stream.recv().await {
        match frame {
            Frame::Data(bytes) => {
                if !bytes.is_empty() && data.send(Vec::from(bytes)).await.is_err() {
                    break;
                }
            }
            Frame::Control(bytes) => {
                if bytes.len() > MAX_CONTROL_BYTES {
                    log::warn!("Dropped a control message on a serial stream: too long");
                } else {
                    handle(&shared, &bytes);
                }
            }
        }
    }
    // The change waiting for an answer will not get one.
    lock(&shared.answers).change = None;
}

fn handle(shared: &Shared, bytes: &[u8]) {
    let message = match ServerMessage::decode(bytes) {
        Ok(message) => message,
        Err(why) => {
            log::warn!("Dropped a control message on a serial stream: {why}");
            return;
        }
    };
    match message {
        ServerMessage::Opened {
            line_settings,
            modem_status,
        } => {
            *lock(&shared.line_settings) = line_settings;
            *lock(&shared.modem_status) = modem_status;
        }
        ServerMessage::LineSettings(applied) => {
            *lock(&shared.line_settings) = applied;
            if let Some(pending) = answer_for(shared, Some(&applied)) {
                let _ = pending.send(Answer::Applied(applied));
            }
        }
        ServerMessage::ModemStatus(status) => {
            *lock(&shared.modem_status) = status;
            let _ = shared.events.send(SerialEvent::ModemStatus(status));
        }
        ServerMessage::Error {
            code: ErrorCode::Unsupported,
            detail,
        } => match answer_for(shared, None) {
            Some(pending) => {
                let _ = pending.send(Answer::Refused(detail));
            }
            None => {
                let _ = shared.events.send(SerialEvent::Error {
                    code: ErrorCode::Unsupported,
                    detail,
                });
            }
        },
        ServerMessage::Error { code, detail } => {
            let _ = shared.events.send(SerialEvent::Error { code, detail });
        }
        other => {
            log::warn!("Ignored a serial control message this end does not use: {other:?}");
        }
    }
}

/// The change an answer belongs to, or `None`. Answers come in the order the changes went out, so
/// one that arrives while an earlier change is still owed its answer is that change's, and is not
/// taken for the pending one; only an echo of exactly the pending change's settings is always its
/// own.
fn answer_for(shared: &Shared, applied: Option<&LineSettings>) -> Option<oneshot::Sender<Answer>> {
    let mut answers = lock(&shared.answers);
    if let (Some(applied), Some(pending)) = (applied, &answers.change)
        && *applied == pending.settings
    {
        answers.owed = 0;
        return answers.change.take().map(|p| p.answer);
    }
    if answers.owed > 0 {
        answers.owed -= 1;
        return None;
    }
    answers.change.take().map(|p| p.answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use skakel_serial::{DataBits, FlowControl, Parity, StopBits};

    fn settings(baud: u32) -> LineSettings {
        LineSettings {
            baud,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            flow_control: FlowControl::None,
        }
    }

    fn shared(pending: Option<(LineSettings, oneshot::Sender<Answer>)>, owed: u32) -> Shared {
        let (events, _) = broadcast::channel(8);
        Shared {
            line_settings: Mutex::new(settings(9600)),
            modem_status: Mutex::new(ModemStatus {
                cts: false,
                dsr: false,
                dcd: false,
                ri: false,
            }),
            answers: Mutex::new(Answers {
                change: pending.map(|(settings, answer)| Pending { settings, answer }),
                owed,
            }),
            events,
        }
    }

    #[test]
    fn an_echo_of_the_pending_change_is_its_answer() {
        let (tx, mut rx) = oneshot::channel();
        let shared = shared(Some((settings(115_200), tx)), 0);

        handle(
            &shared,
            &ServerMessage::LineSettings(settings(115_200)).encode(),
        );

        assert!(matches!(rx.try_recv(), Ok(Answer::Applied(s)) if s.baud == 115_200));
        assert_eq!(lock(&shared.line_settings).baud, 115_200);
    }

    #[test]
    fn an_answer_that_comes_while_a_late_one_is_owed_is_not_taken_for_the_pending_change() {
        let (tx, mut rx) = oneshot::channel();
        let shared = shared(Some((settings(1200), tx)), 1);

        // The slow change's echo, which is not what the pending change asked for.
        handle(
            &shared,
            &ServerMessage::LineSettings(settings(4800)).encode(),
        );

        assert!(rx.try_recv().is_err(), "still waiting");
        assert_eq!(lock(&shared.answers).owed, 0);
        assert_eq!(
            lock(&shared.line_settings).baud,
            4800,
            "the settings still follow the server"
        );

        // Now the pending change's own refusal.
        handle(
            &shared,
            &ServerMessage::Error {
                code: ErrorCode::Unsupported,
                detail: Some("no".into()),
            }
            .encode(),
        );

        assert!(matches!(rx.try_recv(), Ok(Answer::Refused(Some(d))) if d == "no"));
    }

    #[test]
    fn an_exact_echo_of_the_pending_change_is_its_own_even_when_answers_are_owed() {
        let (tx, mut rx) = oneshot::channel();
        let shared = shared(Some((settings(1200), tx)), 2);

        handle(
            &shared,
            &ServerMessage::LineSettings(settings(1200)).encode(),
        );

        assert!(matches!(rx.try_recv(), Ok(Answer::Applied(_))));
        assert_eq!(lock(&shared.answers).owed, 0);
    }

    #[test]
    fn an_unsupported_error_with_no_change_waiting_is_an_event() {
        let shared = shared(None, 0);
        let mut events = shared.events.subscribe();

        handle(
            &shared,
            &ServerMessage::Error {
                code: ErrorCode::Unsupported,
                detail: Some("x".into()),
            }
            .encode(),
        );

        assert_eq!(
            events.try_recv().unwrap(),
            SerialEvent::Error {
                code: ErrorCode::Unsupported,
                detail: Some("x".into())
            }
        );
    }

    #[test]
    fn modem_status_and_other_errors_are_events_and_update_the_state() {
        let shared = shared(None, 0);
        let mut events = shared.events.subscribe();

        handle(
            &shared,
            &ServerMessage::ModemStatus(ModemStatus {
                cts: true,
                dsr: true,
                dcd: false,
                ri: false,
            })
            .encode(),
        );
        handle(
            &shared,
            &ServerMessage::Error {
                code: ErrorCode::Parity,
                detail: None,
            }
            .encode(),
        );

        assert!(lock(&shared.modem_status).cts);
        assert!(matches!(events.try_recv().unwrap(), SerialEvent::ModemStatus(s) if s.dsr));
        assert_eq!(
            events.try_recv().unwrap(),
            SerialEvent::Error {
                code: ErrorCode::Parity,
                detail: None
            }
        );
    }

    #[test]
    fn a_message_that_is_not_a_serial_message_is_dropped() {
        let shared = shared(None, 0);

        handle(&shared, &[0x2A, 0x00]);
        handle(&shared, b"not protobuf");

        assert_eq!(lock(&shared.line_settings).baud, 9600);
    }

    #[test]
    fn an_echo_with_a_value_this_end_does_not_know_still_answers_the_pending_change() {
        let (tx, mut rx) = oneshot::channel();
        let shared = shared(Some((settings(115_200), tx)), 0);
        let echo = skakel_proto::v2::SerialServerMessage {
            message: Some(
                skakel_proto::v2::serial_server_message::Message::LineSettings(
                    skakel_proto::v2::LineSettings {
                        baud: 115_200,
                        data_bits: 8,
                        parity: 42,
                        stop_bits: 1,
                        flow_control: 1,
                    },
                ),
            ),
        };

        handle(&shared, &prost::Message::encode_to_vec(&echo));

        assert!(
            matches!(rx.try_recv(), Ok(Answer::Applied(s)) if s.parity == Parity::Unknown(42)),
            "the change is answered at once, not left to time out"
        );
        assert_eq!(lock(&shared.line_settings).parity, Parity::Unknown(42));
    }

    #[test]
    fn an_error_code_this_end_does_not_know_is_an_event_and_does_not_refuse_the_change() {
        let (tx, mut rx) = oneshot::channel();
        let shared = shared(Some((settings(1200), tx)), 0);
        let mut events = shared.events.subscribe();

        handle(
            &shared,
            &ServerMessage::Error {
                code: ErrorCode::Unknown(77),
                detail: None,
            }
            .encode(),
        );

        assert!(rx.try_recv().is_err(), "the change is still waiting");
        assert_eq!(
            events.try_recv().unwrap(),
            SerialEvent::Error {
                code: ErrorCode::Unknown(77),
                detail: None
            }
        );
    }
}
