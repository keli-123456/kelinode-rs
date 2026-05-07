use std::future::Future;
use std::pin::Pin;

use crate::realtime::{
    realtime_runtime_task, RealtimeMessage, RealtimeOptions, RealtimeRuntimeTask,
};

pub type RealtimeTransportFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

pub trait RealtimeTransport {
    fn send<'a>(&'a mut self, message: RealtimeMessage) -> RealtimeTransportFuture<'a, ()>;
    fn recv<'a>(&'a mut self) -> RealtimeTransportFuture<'a, Option<RealtimeMessage>>;
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
                vec![build_realtime_receipt(
                    "users",
                    source,
                    "received",
                    "",
                    201,
                )]
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
