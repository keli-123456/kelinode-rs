use std::future::Future;
use std::pin::Pin;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

use crate::realtime::{
    build_realtime_dial_url, realtime_runtime_task, RealtimeMessage, RealtimeOptions,
    RealtimeRuntimeTask,
};

pub type RealtimeTransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

pub trait RealtimeTransport {
    fn send<'a>(&'a mut self, message: RealtimeMessage) -> RealtimeTransportFuture<'a, ()>;
    fn recv<'a>(&'a mut self) -> RealtimeTransportFuture<'a, Option<RealtimeMessage>>;
}

pub struct TokioTungsteniteTransport {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl TokioTungsteniteTransport {
    pub async fn connect(raw_url: &str) -> Result<Self, String> {
        let (stream, _) = connect_async(raw_url)
            .await
            .map_err(|err| format!("connect realtime websocket: {err}"))?;
        Ok(Self { stream })
    }
}

pub async fn connect_realtime_transport(
    options: &RealtimeOptions,
) -> Result<TokioTungsteniteTransport, String> {
    let dial_url = build_realtime_dial_url(options)?;
    TokioTungsteniteTransport::connect(&dial_url).await
}

impl RealtimeTransport for TokioTungsteniteTransport {
    fn send<'a>(&'a mut self, message: RealtimeMessage) -> RealtimeTransportFuture<'a, ()> {
        Box::pin(async move {
            let payload = serde_json::to_string(&message)
                .map_err(|err| format!("encode realtime message: {err}"))?;
            self.stream
                .send(Message::Text(payload.into()))
                .await
                .map_err(|err| format!("send realtime message: {err}"))
        })
    }

    fn recv<'a>(&'a mut self) -> RealtimeTransportFuture<'a, Option<RealtimeMessage>> {
        Box::pin(async move {
            loop {
                let Some(frame) = self.stream.next().await else {
                    return Ok(None);
                };
                let frame = frame.map_err(|err| format!("read realtime message: {err}"))?;
                match frame {
                    Message::Text(text) => {
                        match serde_json::from_str::<RealtimeMessage>(text.as_str()) {
                            Ok(message) => return Ok(Some(message)),
                            Err(_) => continue,
                        }
                    }
                    Message::Binary(bytes) => {
                        match serde_json::from_slice::<RealtimeMessage>(bytes.as_ref()) {
                            Ok(message) => return Ok(Some(message)),
                            Err(_) => continue,
                        }
                    }
                    Message::Ping(bytes) => {
                        self.stream
                            .send(Message::Pong(bytes))
                            .await
                            .map_err(|err| format!("send realtime pong frame: {err}"))?;
                    }
                    Message::Close(_) => return Ok(None),
                    _ => {}
                }
            }
        })
    }
}

pub async fn serve_realtime_transport<T, F, N>(
    options: &RealtimeOptions,
    transport: &mut T,
    mut now_ts: N,
    mut on_task: F,
) -> Result<(), String>
where
    T: RealtimeTransport,
    F: FnMut(RealtimeRuntimeTask, &RealtimeMessage) -> Vec<RealtimeMessage>,
    N: FnMut() -> i64,
{
    transport
        .send(RealtimeMessage::ping(options, now_ts(), None))
        .await?;

    while let Some(message) = transport.recv().await? {
        let task = realtime_runtime_task(&message, now_ts());
        if let RealtimeRuntimeTask::Pong(pong) = &task {
            transport.send(pong.clone()).await?;
        }
        if matches!(task, RealtimeRuntimeTask::Ignore) {
            continue;
        }

        for outbound in on_task(task, &message) {
            transport.send(outbound).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use crate::realtime::{
        build_realtime_receipt, RealtimeMessage, RealtimeOptions, RealtimeRuntimeTask,
    };

    use super::{serve_realtime_transport, RealtimeTransport};

    #[tokio::test]
    async fn sends_initial_ping_and_replies_to_panel_ping() {
        let mut transport = MemoryTransport::new(vec![RealtimeMessage {
            message_type: "ping".to_string(),
            ..RealtimeMessage::default()
        }]);
        let mut ts = 100;
        let mut tasks = Vec::new();
        let options = test_options();

        serve_realtime_transport(
            &options,
            &mut transport,
            || {
                ts += 1;
                ts
            },
            |task, _| {
                tasks.push(task);
                Vec::new()
            },
        )
        .await
        .unwrap();

        assert_eq!(transport.sent.len(), 2);
        assert_eq!(transport.sent[0].message_type, "ping");
        assert_eq!(transport.sent[0].token, "token");
        assert_eq!(transport.sent[0].node_id, "7");
        assert_eq!(transport.sent[0].machine_id, 3);
        assert_eq!(transport.sent[0].ts, 101);
        assert_eq!(transport.sent[1], RealtimeMessage::pong(102));
        assert!(matches!(&tasks[0], RealtimeRuntimeTask::Pong(_)));
    }

    #[tokio::test]
    async fn dispatches_invalidate_tasks_and_sends_handler_messages() {
        let invalidate = RealtimeMessage {
            message_type: "invalidate".to_string(),
            topic: "users".to_string(),
            event_id: "evt-1".to_string(),
            reason: "user.delta".to_string(),
            ..RealtimeMessage::default()
        };
        let mut transport = MemoryTransport::new(vec![invalidate]);
        let mut tasks = Vec::new();
        let options = test_options();

        serve_realtime_transport(
            &options,
            &mut transport,
            || 200,
            |task, source| {
                tasks.push(task);
                vec![build_realtime_receipt("users", source, "received", "", 201)]
            },
        )
        .await
        .unwrap();

        assert_eq!(tasks, vec![RealtimeRuntimeTask::UserSync]);
        assert_eq!(transport.sent.len(), 2);
        assert_eq!(transport.sent[1].message_type, "receipt");
        assert_eq!(transport.sent[1].topic, "users");
        assert_eq!(transport.sent[1].event_id, "evt-1");
        assert_eq!(transport.sent[1].status, "received");
    }

    fn test_options() -> RealtimeOptions {
        RealtimeOptions {
            url: "wss://panel.example.test/ws/node".to_string(),
            token: "token".to_string(),
            node_id: 7,
            machine_id: 3,
            ..RealtimeOptions::default()
        }
    }

    struct MemoryTransport {
        inbound: VecDeque<RealtimeMessage>,
        sent: Vec<RealtimeMessage>,
    }

    impl MemoryTransport {
        fn new(inbound: Vec<RealtimeMessage>) -> Self {
            Self {
                inbound: inbound.into_iter().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl RealtimeTransport for MemoryTransport {
        fn send<'a>(
            &'a mut self,
            message: RealtimeMessage,
        ) -> super::RealtimeTransportFuture<'a, ()> {
            Box::pin(async move {
                self.sent.push(message);
                Ok(())
            })
        }

        fn recv<'a>(&'a mut self) -> super::RealtimeTransportFuture<'a, Option<RealtimeMessage>> {
            Box::pin(async move { Ok(self.inbound.pop_front()) })
        }
    }
}
