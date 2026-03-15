pub mod processor;
pub mod pubsub;

use crate::poller::processor::Processor;
use crate::poller::pubsub::PubSubClient;

pub async fn run_poller(pubsub: PubSubClient, processor: Processor) {
    let mut backoff_secs = 1u64;
    loop {
        match pubsub.pull().await {
            Ok(messages) if !messages.is_empty() => {
                backoff_secs = 1;
                let ack_ids: Vec<_> = messages.iter().map(|m| m.ack_id.clone()).collect();
                if let Err(e) = processor.process_notifications(messages).await {
                    tracing::error!("Error processing notifications: {e}");
                }
                if let Err(e) = pubsub.acknowledge(ack_ids).await {
                    tracing::error!("Error acknowledging messages: {e}");
                }
            }
            Ok(_) => {
                // Empty response (timeout) -- immediately loop back
                backoff_secs = 1;
            }
            Err(e) => {
                tracing::error!("Pub/Sub pull error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}
